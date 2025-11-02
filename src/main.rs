use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;

pub mod config;
pub mod local;
pub mod nat;
pub mod tunnel;

use config::Config;
use tokio::select;

use crate::nat::{AddressTranslator, Protocol};
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

    let mut port_forward = HashMap::new();
    for peer in config.server.peers.iter() {
        for tcp_port in peer.tcp_port_forward.iter() {
            port_forward.insert((Protocol::Tcp, *tcp_port), peer.peer_address);
        };

        for udp_port in peer.udp_port_forward.iter() {
            port_forward.insert((Protocol::Udp, *udp_port), peer.peer_address);
        };
    }
    let mut nat = AddressTranslator::new(config.client.address, port_forward);

    loop {
        select! {
            Some(mut data) = client_channel.recv() => {
                if nat.translate_inward(&mut data).is_some() {
                    server_channel.send(data).await.ok();
                }
            },
            Some(mut data) = server_channel.recv() => {
                match process_local(&mut data, config.server.address).await {
                    local::ProcessLocalResult::Done => continue,
                    local::ProcessLocalResult::WriteBack => {
                        server_channel.send(data).await.ok();
                        continue;
                    },
                    local::ProcessLocalResult::NotLocal => (),
                };

                if nat.translate_outward(&mut data).is_some() {
                    client_channel.send(data).await.ok();
                }
            }
        }
    }
}
