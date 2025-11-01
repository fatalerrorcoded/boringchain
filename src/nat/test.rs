use std::net::Ipv4Addr;

use etherparse::{IcmpEchoHeader, Icmpv4Type, PacketBuilder, SlicedPacket};
use etherparse::icmpv4::{DestUnreachableHeader, TimeExceededCode};

use crate::nat::{AddressTranslator, NatKey, Protocol};

#[test]
fn inward_key_tcp() {
    let nat = AddressTranslator::new(Ipv4Addr::UNSPECIFIED);
    // inward: we receive a packet from the ip 1.1.1.1 to port 12345
    let builder = PacketBuilder::ipv4([1, 1, 1, 1], [192, 168, 1, 1], 20).tcp(80, 12345, 0, 0);
    let mut data = Vec::with_capacity(builder.size(0));
    builder.write(&mut data, &[]).unwrap();

    let packet = SlicedPacket::from_ip(&data).unwrap();
    let net_slice = packet.net.unwrap();
    let ip_slice = net_slice.ipv4_ref().unwrap();
    let ip_source = ip_slice.header().source_addr();

    let key = nat
        .get_inward_key(packet.transport.unwrap(), ip_source)
        .unwrap();
    assert_eq!(key, NatKey::new(Protocol::Tcp, 12345, None));
}

#[test]
fn inward_key_udp() {
    let nat = AddressTranslator::new(Ipv4Addr::UNSPECIFIED);
    // inward: we receive a packet from the ip 1.1.1.1 to port 12345
    let builder = PacketBuilder::ipv4([1, 1, 1, 1], [192, 168, 1, 1], 20).udp(53, 12345);
    let mut data = Vec::with_capacity(builder.size(0));
    builder.write(&mut data, &[]).unwrap();

    let packet = SlicedPacket::from_ip(&data).unwrap();
    let net_slice = packet.net.unwrap();
    let ip_slice = net_slice.ipv4_ref().unwrap();
    let ip_source = ip_slice.header().source_addr();

    let key = nat
        .get_inward_key(packet.transport.unwrap(), ip_source)
        .unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, 12345, None));
}

#[test]
fn inward_key_icmp_echo() {
    let nat = AddressTranslator::new(Ipv4Addr::UNSPECIFIED);
    // inward: we receive an icmp echo reply from the ip 1.1.1.1 with id 12345
    let builder = PacketBuilder::ipv4([1, 1, 1, 1], [192, 168, 1, 1], 20)
        .icmpv4(Icmpv4Type::EchoReply(IcmpEchoHeader { id: 12345, seq: 0 }));
    let mut data = Vec::with_capacity(builder.size(0));
    builder.write(&mut data, &[]).unwrap();

    let packet = SlicedPacket::from_ip(&data).unwrap();
    let net_slice = packet.net.unwrap();
    let ip_slice = net_slice.ipv4_ref().unwrap();
    let ip_source = ip_slice.header().source_addr();

    let key = nat
        .get_inward_key(packet.transport.unwrap(), ip_source)
        .unwrap();
    assert_eq!(key, NatKey::new(Protocol::Icmp, 12345, None));
}

#[test]
fn inward_key_icmp_error() {
    let nat = AddressTranslator::new(Ipv4Addr::UNSPECIFIED);
    // inward: we receive a response from the router 1.2.3.4, saying that
    // a packet sent to ip 1.1.1.1 from port 12345 timed out
    let udp_builder = PacketBuilder::ipv4([192, 168, 1, 1], [1, 1, 1, 1], 3).udp(12345, 53);
    let mut udp_data = Vec::with_capacity(udp_builder.size(0));
    udp_builder.write(&mut udp_data, &[]).unwrap();

    let builder = PacketBuilder::ipv4([1, 2, 3, 4], [192, 168, 1, 1], 20).icmpv4(
        Icmpv4Type::TimeExceeded(TimeExceededCode::TtlExceededInTransit),
    );
    let mut data = Vec::with_capacity(builder.size(udp_data.len()));
    builder.write(&mut data, &udp_data).unwrap();

    let packet = SlicedPacket::from_ip(&data).unwrap();
    let net_slice = packet.net.unwrap();
    let ip_slice = net_slice.ipv4_ref().unwrap();
    let ip_source = ip_slice.header().source_addr();

    let key = nat
        .get_inward_key(packet.transport.unwrap(), ip_source)
        .unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, 12345, None));
}

#[test]
fn outward_key_tcp() {
    let nat = AddressTranslator::new(Ipv4Addr::UNSPECIFIED);
    // outward: we send a packet from the ip 192:168.1.1 from port 12345
    let builder = PacketBuilder::ipv4([192, 168, 1, 1], [1, 1, 1, 1], 20).tcp(12345, 80, 0, 0);
    let mut data = Vec::with_capacity(builder.size(0));
    builder.write(&mut data, &[]).unwrap();

    let packet = SlicedPacket::from_ip(&data).unwrap();
    let net_slice = packet.net.unwrap();
    let ip_slice = net_slice.ipv4_ref().unwrap();
    let ip_source = ip_slice.header().source_addr();

    let key = nat
        .get_outward_key(packet.transport.unwrap(), ip_source)
        .unwrap();
    assert_eq!(
        key,
        NatKey::new(Protocol::Tcp, 12345, Some(Ipv4Addr::new(192, 168, 1, 1)))
    );
}

#[test]
fn outward_key_udp() {
    let nat = AddressTranslator::new(Ipv4Addr::UNSPECIFIED);
    // outward: we send a packet from the ip 192.168.1.1 from port 12345
    let builder = PacketBuilder::ipv4([192, 168, 1, 1], [1, 1, 1, 1], 20).udp(12345, 53);
    let mut data = Vec::with_capacity(builder.size(0));
    builder.write(&mut data, &[]).unwrap();

    let packet = SlicedPacket::from_ip(&data).unwrap();
    let net_slice = packet.net.unwrap();
    let ip_slice = net_slice.ipv4_ref().unwrap();
    let ip_source = ip_slice.header().source_addr();

    let key = nat
        .get_outward_key(packet.transport.unwrap(), ip_source)
        .unwrap();
    assert_eq!(
        key,
        NatKey::new(Protocol::Udp, 12345, Some(Ipv4Addr::new(192, 168, 1, 1)))
    );
}

#[test]
fn outward_key_icmp_echo() {
    let nat = AddressTranslator::new(Ipv4Addr::UNSPECIFIED);
    // inward: we send an icmp echo request from the ip 1.1.1.1 with id 12345
    let builder = PacketBuilder::ipv4([192, 168, 1, 1], [1, 1, 1, 1], 20)
        .icmpv4(Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 12345, seq: 0 }));
    let mut data = Vec::with_capacity(builder.size(0));
    builder.write(&mut data, &[]).unwrap();

    let packet = SlicedPacket::from_ip(&data).unwrap();
    let net_slice = packet.net.unwrap();
    let ip_slice = net_slice.ipv4_ref().unwrap();
    let ip_source = ip_slice.header().source_addr();

    let key = nat
        .get_outward_key(packet.transport.unwrap(), ip_source)
        .unwrap();
    assert_eq!(key, NatKey::new(Protocol::Icmp, 12345, Some(Ipv4Addr::new(192, 168, 1, 1))));
}

#[test]
fn outward_key_icmp_error() {
    let nat = AddressTranslator::new(Ipv4Addr::UNSPECIFIED);
    // inward: we send a response to 1.2.3.4, saying that
    // a packet received to port 12345 reached a closed port
    let udp_builder = PacketBuilder::ipv4([1, 2, 3, 4], [192, 168, 1, 1], 20).udp(5678, 12345);
    let mut udp_data = Vec::with_capacity(udp_builder.size(0));
    udp_builder.write(&mut udp_data, &[]).unwrap();

    let builder = PacketBuilder::ipv4([192, 168, 1, 1], [1, 2, 3, 4], 20).icmpv4(
        Icmpv4Type::DestinationUnreachable(DestUnreachableHeader::Port),
    );
    let mut data = Vec::with_capacity(builder.size(udp_data.len()));
    builder.write(&mut data, &udp_data).unwrap();

    let packet = SlicedPacket::from_ip(&data).unwrap();
    let net_slice = packet.net.unwrap();
    let ip_slice = net_slice.ipv4_ref().unwrap();
    let ip_source = ip_slice.header().source_addr();

    let key = nat
        .get_outward_key(packet.transport.unwrap(), ip_source)
        .unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, 12345, Some(Ipv4Addr::new(192, 168, 1, 1))));
}
