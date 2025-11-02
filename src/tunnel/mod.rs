use smoltcp::wire::Ipv4Packet;
use tokio::sync::mpsc::error::TrySendError;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::time::{self, Duration, Instant};

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Index, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, mpsc};

pub mod channel;
pub use channel::*;

use crate::config::ConfigServerPeer;

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const IN_BUF_SIZE: usize = 256;
const OUT_BUF_SIZE: usize = 128;
const TIMER_TASK_BUF_SIZE: usize = 32;

#[derive(Clone)]
pub struct TunnelPeer {
    public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    endpoint: Option<SocketAddr>,
    peer_address: Ipv4Addr,
}

impl TunnelPeer {
    pub fn new(
        public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        endpoint: Option<SocketAddr>,
        peer_address: Ipv4Addr,
    ) -> Self {
        TunnelPeer {
            public_key,
            preshared_key,
            endpoint,
            peer_address,
        }
    }
}

impl From<&ConfigServerPeer> for TunnelPeer {
    fn from(peer: &ConfigServerPeer) -> Self {
        TunnelPeer::new(
            peer.public_key,
            peer.preshared_key,
            peer.endpoint,
            peer.peer_address,
        )
    }
}

pub struct TunnelPeerState {
    tunnel: Tunn,
    endpoint: Option<SocketAddr>,
    def: TunnelPeer,
}

pub struct TunnelManager {
    listen_port: u16,

    private_key: StaticSecret,
    public_key: PublicKey,
    rate_limiter: Arc<RateLimiter>,

    peers: HashMap<PublicKey, Mutex<TunnelPeerState>>,
    idx_to_peer: HashMap<u32, PublicKey>,
    addr_to_peer: HashMap<[u8; 4], PublicKey>,
    is_single: bool,
}

impl TunnelManager {
    pub fn new_single(listen_port: u16, private_key: [u8; 32], peer: TunnelPeer) -> Arc<Self> {
        let mut manager = TunnelManager::new_inner(listen_port, private_key, &[peer]);
        manager.is_single = true;
        Arc::new(manager)
    }

    pub fn new(listen_port: u16, private_key: [u8; 32], peers: &[TunnelPeer]) -> Arc<Self> {
        Arc::new(TunnelManager::new_inner(listen_port, private_key, peers))
    }

    fn new_inner(listen_port: u16, private_key: [u8; 32], peers: &[TunnelPeer]) -> Self {
        let private_key = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&private_key);

        let rate_limiter = Arc::new(RateLimiter::new_at(
            &public_key,
            HANDSHAKE_RATE_LIMIT,
            Instant::now().into_std(),
        ));

        let mut peer_state = HashMap::new();
        let mut idx_to_peer = HashMap::new();
        let mut addr_to_peer = HashMap::new();
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
                Instant::now().into_std(),
            );

            let server_peer = TunnelPeerState {
                tunnel,
                endpoint: peer.endpoint,
                def: peer.clone(),
            };
            peer_state.insert(peer_public_key, Mutex::new(server_peer));
            idx_to_peer.insert(index, peer_public_key);
            addr_to_peer.insert(peer.peer_address.octets(), peer_public_key);
        }

        TunnelManager {
            listen_port,
            private_key,
            public_key,
            rate_limiter,

            peers: peer_state,
            idx_to_peer,
            addr_to_peer,
            is_single: false,
        }
    }

    pub async fn run(self: Arc<Self>) -> TunnelManagerChannel {
        let (send_out, recv_out) = mpsc::channel(OUT_BUF_SIZE);
        let (send_in, recv_in) = mpsc::channel(IN_BUF_SIZE);
        let (send_timer_pkt, recv_timer_pkt) = mpsc::channel(TIMER_TASK_BUF_SIZE);

        let _socket_task =
            tokio::task::spawn(self.clone().run_socket(recv_in, send_out, recv_timer_pkt));
        let _limiter_timer_task = tokio::task::spawn(self.clone().run_limiter_timer());
        let _peer_timer_task = tokio::task::spawn(self.clone().run_peer_timer(send_timer_pkt));

        TunnelManagerChannel::new(send_in, recv_out)
    }

    async fn run_socket(
        self: Arc<Self>,
        mut recv_in: Receiver<Vec<u8>>,
        send_out: Sender<Vec<u8>>,
        mut recv_timer_pkt: Receiver<(SocketAddr, Vec<u8>)>,
    ) {
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

                    self.process_incoming(&socket, addr, &src_buf[..amt], &mut dst_buf, send_out.clone()).await;
                },
                Some(data) = recv_in.recv() => {
                    self.process_outgoing(&socket, &data, &mut dst_buf).await;
                }
                Some((addr, packet)) = recv_timer_pkt.recv() => {
                    socket.send_to(&packet, addr).await.ok();
                },
            };
        }
    }

    async fn process_incoming(
        &self,
        socket: &UdpSocket,
        addr: SocketAddr,
        src: &[u8],
        dst: &mut [u8],
        send_out: Sender<Vec<u8>>,
    ) {
        let packet = match self.rate_limiter.verify_packet_at(
            Some(addr.ip()),
            src,
            dst,
            Instant::now().into_std(),
        ) {
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

        let mut peer = peer_mutex.lock().await;
        let mut flush = false;

        match peer
            .tunnel
            .decapsulate_at(Some(addr.ip()), src, dst, Instant::now().into_std())
        {
            TunnResult::Done => (),
            TunnResult::Err(_) => (),
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                socket.send_to(packet, addr).await.ok();
            }
            TunnResult::WriteToTunnelV4(packet, ipv4_addr) => {
                // reject packets from a client if their address is different
                if ipv4_addr == peer.def.peer_address || self.is_single {
                    // drop overflow
                    send_out.try_send(Vec::from(packet)).ok();
                }
            }
            TunnResult::WriteToTunnelV6(_, _) => (), // we do not support IPv6 (yet)
        }

        peer.endpoint = Some(addr);
        if flush {
            while let TunnResult::WriteToNetwork(packet) =
                peer.tunnel
                    .decapsulate_at(None, &[], dst, Instant::now().into_std())
            {
                socket.send_to(packet, &addr).await.ok();
            }
        }
    }

    async fn process_outgoing(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        dst: &mut [u8],
    ) -> Option<()> {
        let peer_mutex = {
            if self.is_single {
                self.peers.values().next()?
            } else {
                let ipv4 = Ipv4Packet::new_unchecked(data);
                let destination = ipv4.dst_addr();
                let mapping = self.addr_to_peer.get(&destination.octets())?;
                self.peers.get(mapping)?
            }
        };

        let mut peer = peer_mutex.lock().await;
        match peer
            .tunnel
            .encapsulate_at(data, dst, Instant::now().into_std())
        {
            TunnResult::Done => (),
            TunnResult::Err(_) => (),
            TunnResult::WriteToNetwork(packet) => {
                if let Some(endpoint) = peer.endpoint {
                    socket.send_to(packet, endpoint).await.ok();
                }
            }
            _ => panic!("Unexpected result from encapsulate"),
        };

        Some(())
    }

    async fn run_limiter_timer(self: Arc<Self>) {
        loop {
            self.rate_limiter.reset_count_at(Instant::now().into_std());
            time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn run_peer_timer(self: Arc<Self>, timer_pkt: Sender<(SocketAddr, Vec<u8>)>) {
        let mut dst_buf = vec![0; MAX_UDP_SIZE];
        loop {
            for peer_mutex in self.peers.values() {
                let Ok(mut peer) = peer_mutex.try_lock() else {
                    continue;
                };

                match peer
                    .tunnel
                    .update_timers_at(&mut dst_buf, Instant::now().into_std())
                {
                    TunnResult::Done => (),
                    TunnResult::Err(WireGuardError::ConnectionExpired) => {
                        peer.endpoint = peer.def.endpoint;
                    }
                    TunnResult::Err(_) => (),
                    TunnResult::WriteToNetwork(packet) => {
                        let Some(socket_addr) = peer.endpoint else {
                            continue;
                        };

                        match timer_pkt
                            .try_send((socket_addr, Vec::from(packet))) {
                                Ok(_) => (),
                                Err(TrySendError::Full(_)) => todo!(), // drop
                                Err(err) => panic!("Error on timer task: {:?}", err),
                            }
                    }
                    _ => panic!("Unexpected result from update_timers"),
                };
            }
            time::sleep(Duration::from_millis(250)).await;
        }
    }

    fn get_peer_by_idx(&self, idx: u32) -> Option<&Mutex<TunnelPeerState>> {
        let global_idx = idx >> 8;
        let key = self.idx_to_peer.get(&global_idx)?;
        self.peers.get(key)
    }
}
