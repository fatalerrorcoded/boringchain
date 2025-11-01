use std::fs;

pub mod config;
pub mod tunnel;

use config::Config;

use crate::tunnel::{TunnelManager, TunnelPeer};

#[tokio::main]
async fn main() {
    let config_data = fs::read("./boringchain.toml").expect("No boringchain.toml config");
    let config: Config = toml::from_slice(&config_data).expect("Invalid config");

    let server_peers: Vec<_> = config.server.peers.iter().map(TunnelPeer::from).collect();
    let mut server_channel = TunnelManager::new(
        config.server.listen_port,
        config.server.private_key,
        &server_peers,
    )
    .run()
    .await;

    while let Some(packet) = server_channel.recv().await {
        println!("{:x?}", packet)
    }
}
