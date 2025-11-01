use std::fs;
use std::net::Ipv4Addr;

pub mod config;
pub mod nat;
pub mod tunnel;
pub mod local;

use config::Config;
use tokio::select;

use crate::nat::AddressTranslator;
use crate::tunnel::{TunnelManager, TunnelPeer};
use local::process_local;

#[tokio::main]
async fn main() {
    let config_data = fs::read("./boringchain.toml").expect("No boringchain.toml config");
    let config: Config = toml::from_slice(&config_data).expect("Invalid config");

    let client_peer = TunnelPeer::new(
        config.client.peer_public_key,
        config.client.peer_preshared_key,
        config.client.peer_endpoint,
        Ipv4Addr::UNSPECIFIED,
    );
    let mut client_channel = TunnelManager::new_single(
        config.client.listen_port,
        config.client.private_key,
        client_peer,
    )
    .run()
    .await;

    let server_peers: Vec<_> = config.server.peers.iter().map(TunnelPeer::from).collect();
    let mut server_channel = TunnelManager::new(
        config.server.listen_port,
        config.server.private_key,
        &server_peers,
    )
    .run()
    .await;

    let mut nat = AddressTranslator::new(config.client.address);

    loop {
        select! {
            Some(data) = client_channel.recv() => {
                if let Some(translated) = nat.translate_inward(&data) {
                    server_channel.send(translated).await.ok();
                }
            },
            Some(mut data) = server_channel.recv() => {
                if process_local(&data, &server_channel, config.server.address).await {
                    continue;
                };

                if let Some(translated) = nat.translate_outward(&mut data) {
                    client_channel.send(translated).await.ok();
                }
            }
        }
    }
}
