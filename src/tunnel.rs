use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Index, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::channel::mpsc::{self, Receiver, Sender};
use futures::{SinkExt, StreamExt, future};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::Mutex;

use crate::config::ConfigServerPeer;

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

#[derive(Clone)]
pub struct TunnelPeer {
    public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    peer_address: Ipv4Addr,
    allow_all: bool,
}

impl TunnelPeer {
    pub fn new(
        public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        peer_address: Ipv4Addr,
        allow_all: bool,
    ) -> Self {
        TunnelPeer {
            public_key,
            preshared_key,
            peer_address,
            allow_all,
        }
    }
}

impl From<&ConfigServerPeer> for TunnelPeer {
    fn from(peer: &ConfigServerPeer) -> Self {
        TunnelPeer::new(
            peer.public_key,
            peer.preshared_key,
            peer.peer_address,
            false,
        )
    }
}

pub struct TunnelPeerState {
    tunnel: Tunn,
    socket_addr: Option<SocketAddr>,
    peer: TunnelPeer,
}

pub struct TunnelManager {
    listen_port: u16,

    private_key: StaticSecret,
    public_key: PublicKey,
    rate_limiter: Arc<RateLimiter>,

    peers: HashMap<PublicKey, Mutex<TunnelPeerState>>,
    idx_to_peer: HashMap<u32, PublicKey>,
}

impl TunnelManager {
    pub fn new(listen_port: u16, private_key: [u8; 32], peers: &[TunnelPeer]) -> Arc<Self> {
        let private_key = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&private_key);

        let rate_limiter = Arc::new(RateLimiter::new_at(
            &public_key,
            HANDSHAKE_RATE_LIMIT,
            Instant::now(),
        ));

        let mut peer_state = HashMap::new();
        let mut idx_to_peer = HashMap::new();
        for peer in peers {
            let peer_public_key = PublicKey::from(peer.public_key);
            let index = rand::random::<u32>() & 0x00FFFFFF;
            let tunnel = Tunn::new_at(
                private_key.clone(),
                peer_public_key,
                peer.preshared_key.map(StaticSecret::from),
                None,
                Index::new_local(index),
                Some(rate_limiter.clone()),
                rand::random(),
                Instant::now(),
            );

            let server_peer = TunnelPeerState {
                tunnel,
                socket_addr: None,
                peer: peer.clone(),
            };
            peer_state.insert(peer_public_key, Mutex::new(server_peer));
            idx_to_peer.insert(index, peer_public_key);
        }

        Arc::new(TunnelManager {
            listen_port,
            private_key,
            public_key,
            rate_limiter,

            peers: peer_state,
            idx_to_peer,
        })
    }

    pub async fn run(self: Arc<Self>) {
        let (send_timer_pkt, recv_timer_pkt) = mpsc::channel(16);

        let socket_task = tokio::task::spawn(self.clone().run_socket(recv_timer_pkt));
        let limiter_timer_task = tokio::task::spawn(self.clone().run_limiter_timer());
        let peer_timer_task = tokio::task::spawn(self.clone().run_peer_timer(send_timer_pkt));
        let _join = future::join3(socket_task, limiter_timer_task, peer_timer_task).await;
    }

    async fn run_socket(self: Arc<Self>, mut recv_timer_pkt: Receiver<(SocketAddr, Vec<u8>)>) {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, self.listen_port))
            .await
            .expect("Failed to create server socket");

        let mut src_buf = vec![0; MAX_UDP_SIZE];
        let mut dst_buf = vec![0; MAX_UDP_SIZE];
        loop {
            select! {
                recv_result = socket.recv_from(&mut src_buf) => {
                    let Ok((amt, addr)) = recv_result else {
                        break;
                    };

                    self.process_packet(&socket, addr, &src_buf[..amt], &mut dst_buf).await;
                },
                Some((addr, packet)) = recv_timer_pkt.next() => {
                    socket.send_to(&packet, addr).await.ok();
                }
            };
        }
    }

    async fn process_packet(
        &self,
        socket: &UdpSocket,
        addr: SocketAddr,
        src: &[u8],
        dst: &mut [u8],
    ) {
        let packet =
            match self
                .rate_limiter
                .verify_packet_at(Some(addr.ip()), src, dst, Instant::now())
            {
                Ok(packet) => packet,
                Err(TunnResult::WriteToNetwork(cookie)) => {
                    socket.send_to(cookie, &addr).await.ok();
                    return;
                }
                Err(_) => {
                    println!("Failed to parse incoming packet from {}", addr);
                    return;
                }
            };

        let peer_mutex = match packet {
            boringtun::noise::Packet::HandshakeInit(init) => {
                parse_handshake_anon(&self.private_key, &self.public_key, &init)
                    .ok()
                    .and_then(|hh| self.peers.get(&PublicKey::from(hh.peer_static_public)))
            }
            boringtun::noise::Packet::HandshakeResponse(res) => {
                self.get_peer_by_idx(res.receiver_idx)
            }
            boringtun::noise::Packet::PacketCookieReply(reply) => {
                self.get_peer_by_idx(reply.receiver_idx)
            }
            boringtun::noise::Packet::PacketData(data) => self.get_peer_by_idx(data.receiver_idx),
        };

        let Some(peer_mutex) = peer_mutex else {
            return;
        };

        let mut peer_state = peer_mutex.lock().await;
        let mut flush = false;

        match peer_state.tunnel.decapsulate_at(Some(addr.ip()), src, dst, Instant::now()) {
            TunnResult::Done => (),
            TunnResult::Err(_) => (),
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                socket.send_to(packet, addr).await.ok();
            }
            TunnResult::WriteToTunnelV4(packet, ipv4_addr) => {
                // reject packets from a client if their address is different
                if ipv4_addr == peer_state.peer.peer_address || peer_state.peer.allow_all {
                    println!("{:x?}", packet);
                }
            }
            TunnResult::WriteToTunnelV6(_, _) => (), // we do not support IPv6 (yet)
        }

        peer_state.socket_addr = Some(addr);
        if flush {
            while let TunnResult::WriteToNetwork(packet) =
                peer_state.tunnel.decapsulate_at(None, &[], dst, Instant::now())
            {
                socket.send_to(packet, &addr).await.ok();
            }
        }
    }

    async fn run_limiter_timer(self: Arc<Self>) {
        loop {
            self.rate_limiter.reset_count_at(Instant::now());
            thread::sleep(Duration::from_secs(1));
        }
    }

    async fn run_peer_timer(self: Arc<Self>, mut timer_pkt: Sender<(SocketAddr, Vec<u8>)>) {
        let mut dst_buf = vec![0; MAX_UDP_SIZE];
        loop {
            for peer_mutex in self.peers.values() {
                let mut peer = peer_mutex.lock().await;
                let Some(socket_addr) = peer.socket_addr else {
                    continue;
                };

                match peer.tunnel.update_timers_at(&mut dst_buf, Instant::now()) {
                    TunnResult::Done => (),
                    TunnResult::Err(WireGuardError::ConnectionExpired) => peer.socket_addr = None,
                    TunnResult::Err(_) => (),
                    TunnResult::WriteToNetwork(packet) => {
                        timer_pkt
                            .send((socket_addr, Vec::from(packet)))
                            .await
                            .unwrap();
                    }
                    _ => panic!("Unexpected result from update_timers"),
                };
            }
            thread::sleep(Duration::from_millis(250));
        }
    }

    fn get_peer_by_idx(&self, idx: u32) -> Option<&Mutex<TunnelPeerState>> {
        let global_idx = idx >> 8;
        let key = self.idx_to_peer.get(&global_idx)?;
        self.peers.get(key)
    }
}
