use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use boringtun::noise::TunnResult;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;

use crate::config::ConfigServer;

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

pub async fn start_server_task(config: ConfigServer) {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, config.listen_port))
        .await
        .expect("Failed to create server socket");
    let mut current_instant = Instant::now();

    let private_key = StaticSecret::from(config.private_key);
    let public_key = PublicKey::from(&private_key);
    let rate_limiter = Arc::new(RateLimiter::new_at(
        &public_key,
        HANDSHAKE_RATE_LIMIT,
        current_instant,
    ));

    let mut src_buf = vec![0; MAX_UDP_SIZE];
    let mut dst_buf = vec![0; MAX_UDP_SIZE];
    while let Ok((amt, addr)) = socket.recv_from(&mut src_buf).await {
        current_instant = Instant::now();
        let packet = match rate_limiter.verify_packet_at(
            Some(addr.ip()),
            &src_buf[..amt],
            &mut dst_buf,
            current_instant,
        ) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                socket.send_to(cookie, &addr).await.ok();
                continue;
            },
            Err(_) => {
                println!("Failed to parse incoming packet from {}", addr);
                continue;
            }
        };

        println!("{:?}", packet);
    }
}
