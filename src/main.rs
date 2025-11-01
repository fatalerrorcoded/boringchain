use std::fs;
use std::net::Ipv4Addr;

pub mod config;
pub mod tunnel;

use config::Config;
use etherparse::{Icmpv4Type, PacketBuilder, SlicedPacket, TransportSlice};

use crate::tunnel::{TunnelManager, TunnelManagerChannel, TunnelPeer};

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

    while let Some(data) = server_channel.recv().await {
        println!("{:x?}", data);
        process_packet(&data, &server_channel, config.server.address).await;
    }
}

async fn process_packet(
    data: &[u8],
    server_channel: &TunnelManagerChannel,
    address: Ipv4Addr,
) -> Option<()> {
    let packet = SlicedPacket::from_ip(data).ok()?;
    let net = packet.net?;
    let ip = net.ipv4_ref()?;
    if ip.header().destination_addr() != address {
        return None;
    }

    let transport = packet.transport?;
    let TransportSlice::Icmpv4(icmp) = transport else {
        return None;
    };

    let Icmpv4Type::EchoRequest(req) = icmp.icmp_type() else {
        return None;
    };

    let builder = PacketBuilder::ipv4(ip.header().destination(), ip.header().source(), 20)
        .icmpv4_echo_reply(req.id, req.seq);

    let mut result: Vec<u8> = Vec::with_capacity(builder.size(icmp.payload().len()));
    builder.write(&mut result, icmp.payload()).unwrap();
    server_channel.send(result).await.ok();

    Some(())
}
