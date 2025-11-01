use std::net::Ipv4Addr;

use etherparse::{Icmpv4Slice, Icmpv4Type, Ipv4Slice, PacketBuilder, SlicedPacket, TransportSlice};

use crate::tunnel::TunnelManagerChannel;

pub async fn process_local(
    data: &[u8],
    server_channel: &TunnelManagerChannel,
    address: Ipv4Addr,
) -> bool {
    let Ok(packet) = SlicedPacket::from_ip(data) else {
        return false;
    };

    let Some(net) = packet.net else {
        return false;
    };
    let Some(ip) = net.ipv4_ref() else {
        return false;
    };
    if ip.header().destination_addr() != address {
        return false;
    }

    match packet.transport {
        Some(TransportSlice::Icmpv4(icmp)) => {
            process_local_icmp(ip, &icmp, server_channel).await;
        }
        _ => (),
    }
    true
}

async fn process_local_icmp(
    ip: &Ipv4Slice<'_>,
    icmp: &Icmpv4Slice<'_>,
    server_channel: &TunnelManagerChannel,
) -> Option<()> {
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
