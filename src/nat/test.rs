use std::net::Ipv4Addr;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, Icmpv4TimeExceeded, IpProtocol, Ipv4Repr,
    TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};

use crate::nat::{AddressTranslator, NatKey, Protocol};

const SOURCE_PORT: u16 = 1234;
const DESTINATION_PORT: u16 = 5678;
const ICMP_ID: u16 = 1357;

const FAKE_IPV4_PKT_SRC: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
const FAKE_IPV4_PKT_DST: Ipv4Addr = Ipv4Addr::new(5, 6, 7, 8);

fn fake_ipv4_repr(protocol: IpProtocol, payload: &[u8]) -> Ipv4Repr {
    Ipv4Repr {
        src_addr: FAKE_IPV4_PKT_SRC,
        dst_addr: FAKE_IPV4_PKT_DST,
        next_header: protocol,
        payload_len: payload.len(),
        hop_limit: 64,
    }
}

fn fake_tcp_packet() -> Vec<u8> {
    let repr = TcpRepr {
        src_port: SOURCE_PORT,
        dst_port: DESTINATION_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(1),
        ack_number: None,
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };

    let mut buffer = vec![0; repr.buffer_len()];
    let mut packet = TcpPacket::new_unchecked(&mut buffer);
    repr.emit(
        &mut packet,
        &FAKE_IPV4_PKT_SRC.into(),
        &FAKE_IPV4_PKT_DST.into(),
        &ChecksumCapabilities::default(),
    );
    buffer
}

fn fake_udp_packet() -> Vec<u8> {
    let repr = UdpRepr {
        src_port: SOURCE_PORT,
        dst_port: DESTINATION_PORT,
    };

    let mut buffer = vec![0; repr.header_len()];
    let mut packet = UdpPacket::new_unchecked(&mut buffer);
    repr.emit(
        &mut packet,
        &FAKE_IPV4_PKT_SRC.into(),
        &FAKE_IPV4_PKT_DST.into(),
        0,
        |_| (), // no payload
        &ChecksumCapabilities::default(),
    );
    buffer
}

fn fake_icmp_packet(repr: Icmpv4Repr) -> Vec<u8> {
    let mut buffer = vec![0; repr.buffer_len()];
    let mut packet = Icmpv4Packet::new_unchecked(&mut buffer);
    repr.emit(&mut packet, &ChecksumCapabilities::default());
    buffer
}

#[test]
fn inward_key_tcp() {
    let tcp = fake_tcp_packet();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_inward_key(IpProtocol::Tcp, &tcp, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Tcp, DESTINATION_PORT, None));
}

#[test]
fn inward_key_udp() {
    let udp = fake_udp_packet();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_inward_key(IpProtocol::Udp, &udp, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, DESTINATION_PORT, None));
}

#[test]
fn inward_key_icmp_echo() {
    let icmp = Icmpv4Repr::EchoReply {
        ident: ICMP_ID,
        seq_no: 1,
        data: &[],
    };

    let data = fake_icmp_packet(icmp);
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_inward_key(IpProtocol::Icmp, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Icmp, ICMP_ID, None));
}

#[test]
fn inward_key_icmp_error() {
    let udp_data = fake_udp_packet();
    let icmp = Icmpv4Repr::TimeExceeded {
        reason: Icmpv4TimeExceeded::TtlExpired,
        header: fake_ipv4_repr(IpProtocol::Udp, &udp_data),
        data: &udp_data,
    };

    let data = fake_icmp_packet(icmp);
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_inward_key(IpProtocol::Icmp, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, SOURCE_PORT, None));
}

#[test]
fn outward_key_tcp() {
    let tcp = fake_tcp_packet();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_outward_key(IpProtocol::Tcp, &tcp, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Tcp, SOURCE_PORT, Some(address)));
}

#[test]
fn outward_key_udp() {
    let udp = fake_udp_packet();
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_outward_key(IpProtocol::Udp, &udp, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Udp, SOURCE_PORT, Some(address)));
}

#[test]
fn outward_key_icmp_echo() {
    let icmp = Icmpv4Repr::EchoRequest {
        ident: ICMP_ID,
        seq_no: 1,
        data: &[],
    };

    let data = fake_icmp_packet(icmp);
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_outward_key(IpProtocol::Icmp, &data, address).unwrap();
    assert_eq!(key, NatKey::new(Protocol::Icmp, ICMP_ID, Some(address)));
}

#[test]
fn outward_key_icmp_error() {
    let udp_data = fake_udp_packet();
    let icmp = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::PortUnreachable,
        header: fake_ipv4_repr(IpProtocol::Udp, &udp_data),
        data: &udp_data,
    };

    let data = fake_icmp_packet(icmp);
    let address = Ipv4Addr::UNSPECIFIED;

    let key = AddressTranslator::get_outward_key(IpProtocol::Icmp, &data, address).unwrap();
    assert_eq!(
        key,
        NatKey::new(Protocol::Udp, DESTINATION_PORT, Some(FAKE_IPV4_PKT_DST))
    );
}
