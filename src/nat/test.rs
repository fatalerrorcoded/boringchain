use std::net::Ipv4Addr;

use ingot::icmp::{IcmpV4, IcmpV4Type};
use ingot::ip::Ipv4;
use ingot::types::Emit;
use ingot::udp::Udp;
use ingot::{ip::IpProtocol, tcp::Tcp};

use crate::nat::{AddressTranslator, NatKey, Protocol};

const SOURCE_PORT: u16 = 1234;
const DESTINATION_PORT: u16 = 5678;
const ICMP_ID: u16 = 1357;

const FAKE_IPV4_PKT_SRC: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
const FAKE_IPV4_PKT_DST: Ipv4Addr = Ipv4Addr::new(5, 6, 7, 8);

fn fake_ipv4_packet(protocol: IpProtocol) -> Ipv4 {
    Ipv4 {
        protocol,
        source: FAKE_IPV4_PKT_SRC.into(),
        destination: FAKE_IPV4_PKT_DST.into(),
        ..Default::default()
    }
}

fn fake_tcp_packet() -> Tcp {
    Tcp {
        source: SOURCE_PORT,
        destination: DESTINATION_PORT,
        ..Default::default()
    }
}

fn fake_udp_packet() -> Udp {
    Udp {
        source: SOURCE_PORT,
        destination: DESTINATION_PORT,
        ..Default::default()
    }
}

#[test]
fn inward_key_tcp() {
    let tcp = fake_tcp_packet();
    let data = tcp.to_vec();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_inward_key(IpProtocol::TCP, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Tcp, DESTINATION_PORT, None));
}

#[test]
fn inward_key_udp() {
    let udp = fake_tcp_packet();
    let data = udp.to_vec();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_inward_key(IpProtocol::UDP, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, DESTINATION_PORT, None));
}

#[test]
fn inward_key_icmp_echo() {
    let id = u16::to_be_bytes(ICMP_ID);
    let icmp = IcmpV4 {
        ty: IcmpV4Type::ECHO_REPLY,
        rest_of_hdr: [id[0], id[1], 0, 0],
        code: 0,
        checksum: 0,
    };

    let data = icmp.to_vec();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_inward_key(IpProtocol::ICMP, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Icmp, ICMP_ID, None));
}

#[test]
fn inward_key_icmp_error() {
    let icmp = IcmpV4 {
        ty: IcmpV4Type::TIME_EXCEEDED,
        rest_of_hdr: [0, 0, 0, 0],
        code: 0,
        checksum: 0,
    };

    let data = (icmp, fake_ipv4_packet(IpProtocol::UDP), fake_udp_packet()).to_vec();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_inward_key(IpProtocol::ICMP, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, SOURCE_PORT, None));
}

#[test]
fn outward_key_tcp() {
    let tcp = fake_tcp_packet();
    let data = tcp.to_vec();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_outward_key(IpProtocol::TCP, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Tcp, SOURCE_PORT, Some(address)));
}

#[test]
fn outward_key_udp() {
    let udp = fake_tcp_packet();
    let data = udp.to_vec();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_outward_key(IpProtocol::UDP, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, SOURCE_PORT, Some(address)));
}

#[test]
fn outward_key_icmp_echo() {
    let id = u16::to_be_bytes(ICMP_ID);
    let icmp = IcmpV4 {
        ty: IcmpV4Type::ECHO_REQUEST,
        rest_of_hdr: [id[0], id[1], 0, 0],
        code: 0,
        checksum: 0,
    };

    let data = icmp.to_vec();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_outward_key(IpProtocol::ICMP, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Icmp, ICMP_ID, Some(address)));
}

#[test]
fn outward_key_icmp_error() {
    let icmp = IcmpV4 {
        ty: IcmpV4Type::DESTINATION_UNREACHABLE,
        rest_of_hdr: [0, 0, 0, 0],
        code: 0,
        checksum: 0,
    };

    let data = (icmp, fake_ipv4_packet(IpProtocol::UDP), fake_udp_packet()).to_vec();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_outward_key(IpProtocol::ICMP, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, DESTINATION_PORT, Some(FAKE_IPV4_PKT_DST)));
}
