use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use smoltcp::wire::{
    IPV4_HEADER_LEN, Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Packet, TCP_HEADER_LEN,
    TcpPacket, UDP_HEADER_LEN, UdpPacket,
};
use tokio::time::Instant;

mod types;
use types::*;

#[cfg(test)]
mod test;

pub struct AddressTranslator {
    public_address: Ipv4Addr,
    inward: HashMap<NatKey, NatEntry>,
    outward: HashMap<NatKey, NatEntry>,
}

impl AddressTranslator {
    pub fn new(public_address: Ipv4Addr) -> Self {
        AddressTranslator {
            public_address,
            inward: HashMap::new(),
            outward: HashMap::new(),
        }
    }

    pub fn translate_outward(&mut self, data: &mut [u8]) -> Option<()> {
        let mut ipv4 = Ipv4Packet::new_checked(data).ok()?;
        let ip_source = ipv4.src_addr();

        let key = Self::get_outward_key(ipv4.next_header(), ipv4.payload_mut(), ip_source)?;
        let entry = self.outward.get_mut(&key);

        if let Some(entry) = entry {
            let new_state = Self::translate_packet(
                &mut ipv4,
                Some(self.public_address),
                None,
                Some(entry.external_port),
                None,
            )?;

            entry.protocol_state.update_state(new_state);
            entry.last_activity = Instant::now();
            self.inward.insert(entry.to_inward_key(), entry.clone());
            return Some(());
        }

        let external_port = self.get_free_external_port(key.protocol, key.port)?;
        let protocol_state = Self::translate_packet(
            &mut ipv4,
            Some(self.public_address),
            None,
            Some(external_port),
            None,
        )?;

        let entry = NatEntry {
            protocol: key.protocol,
            protocol_state,
            external_port,
            internal: SocketAddrV4::new(ip_source, key.port),
            last_activity: Instant::now(),
        };

        self.inward.insert(entry.to_inward_key(), entry.clone());
        self.outward.insert(entry.to_outward_key(), entry);
        Some(())
    }

    pub fn translate_inward(&mut self, data: &mut [u8]) -> Option<()> {
        let mut ipv4 = Ipv4Packet::new_checked(data).ok()?;
        let ip_source = ipv4.src_addr();

        let key = Self::get_inward_key(ipv4.next_header(), ipv4.payload_mut(), ip_source)?;
        let entry = self.inward.get_mut(&key)?; // drop incoming packet without corresponding nat entry

        let new_state = Self::translate_packet(
            &mut ipv4,
            None,
            Some(*entry.internal.ip()),
            None,
            Some(entry.internal.port()),
        )?;

        entry.protocol_state.update_state(new_state);
        entry.last_activity = Instant::now();
        self.outward.insert(entry.to_outward_key(), entry.clone());
        Some(())
    }

    fn get_inward_key(protocol: IpProtocol, payload: &[u8], source: Ipv4Addr) -> Option<NatKey> {
        Self::get_key(protocol, payload, source, false, false)
    }

    fn get_outward_key(protocol: IpProtocol, payload: &[u8], source: Ipv4Addr) -> Option<NatKey> {
        Self::get_key(protocol, payload, source, true, true)
    }

    fn get_key(
        protocol: IpProtocol,
        payload: &[u8],
        source: Ipv4Addr,
        is_outward: bool,
        reversed: bool,
    ) -> Option<NatKey> {
        match protocol {
            IpProtocol::Tcp => {
                if payload.len() < TCP_HEADER_LEN {
                    return None;
                }
                let tcp = TcpPacket::new_unchecked(payload);
                let port = if reversed {
                    tcp.src_port()
                } else {
                    tcp.dst_port()
                };
                Some(NatKey::new(
                    Protocol::Tcp,
                    port,
                    is_outward.then_some(source),
                ))
            }
            IpProtocol::Udp => {
                if payload.len() < UDP_HEADER_LEN {
                    return None;
                }
                let udp = UdpPacket::new_unchecked(payload);
                let port = if reversed {
                    udp.src_port()
                } else {
                    udp.dst_port()
                };
                // if outward, provide originator - ensures correct NAT operation
                // if inward, do not provide originator - this turns NAT from symmetric to full cone
                Some(NatKey::new(
                    Protocol::Udp,
                    port,
                    is_outward.then_some(source),
                ))
            }
            IpProtocol::Icmp => {
                let icmp = Icmpv4Packet::new_checked(payload).ok()?;
                match icmp.msg_type() {
                    Icmpv4Message::DstUnreachable
                    | Icmpv4Message::Redirect
                    | Icmpv4Message::TimeExceeded
                    | Icmpv4Message::ParamProblem => {
                        let icmp_payload = icmp.data();
                        if icmp_payload.len() < IPV4_HEADER_LEN {
                            return None;
                        }

                        let ipv4 = Ipv4Packet::new_unchecked(icmp_payload);
                        ipv4.verify_checksum().then_some(())?;
                        Self::get_key(
                            ipv4.next_header(),
                            ipv4.payload(),
                            ipv4.dst_addr(),
                            is_outward,
                            !reversed,
                        )
                    }
                    Icmpv4Message::EchoRequest
                    | Icmpv4Message::EchoReply
                    | Icmpv4Message::Timestamp
                    | Icmpv4Message::TimestampReply => Some(NatKey::new(
                        Protocol::Icmp,
                        icmp.echo_ident(),
                        is_outward.then_some(source),
                    )),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn get_free_external_port(&mut self, protocol: Protocol, wanted_port: u16) -> Option<u16> {
        if !self
            .inward
            .contains_key(&NatKey::new(protocol, wanted_port, None))
        {
            return Some(wanted_port);
        }

        let starting_port: u16 = rand::random();
        let mut current_port = starting_port.wrapping_add(1);
        while current_port != starting_port {
            if current_port == 0 {
                continue;
            }

            if !self
                .inward
                .contains_key(&NatKey::new(protocol, wanted_port, None))
            {
                return Some(wanted_port);
            }

            current_port = current_port.wrapping_add(1);
        }

        None
    }

    fn translate_packet(
        ipv4: &mut Ipv4Packet<&mut [u8]>,
        src: Option<Ipv4Addr>,
        dest: Option<Ipv4Addr>,
        src_port: Option<u16>,
        dest_port: Option<u16>,
    ) -> Option<ProtocolState> {
        if let Some(src) = src {
            ipv4.set_src_addr(src);
        }

        if let Some(dest) = dest {
            ipv4.set_dst_addr(dest);
        }

        let src_addr = &ipv4.src_addr().into();
        let dst_addr = &ipv4.dst_addr().into();

        let new_state = match ipv4.next_header() {
            IpProtocol::Tcp => {
                let mut tcp = TcpPacket::new_unchecked(ipv4.payload_mut());
                if let Some(src_port) = src_port {
                    tcp.set_src_port(src_port);
                }
                if let Some(dest_port) = dest_port {
                    tcp.set_dst_port(dest_port);
                }

                tcp.fill_checksum(src_addr, dst_addr);
                match tcp {
                    _ if tcp.rst() => Some(ProtocolState::TcpClosed),
                    _ if tcp.fin() && tcp.ack() => Some(ProtocolState::TcpClosing),
                    _ if tcp.fin() => Some(ProtocolState::TcpClosing),
                    _ if tcp.syn() && tcp.ack() => Some(ProtocolState::TcpSynReceived),
                    _ if tcp.syn() => Some(ProtocolState::TcpSynSent),
                    _ => Some(ProtocolState::TcpEstablished),
                }
            }
            IpProtocol::Udp => {
                let mut udp = UdpPacket::new_unchecked(ipv4.payload_mut());
                if let Some(src_port) = src_port {
                    udp.set_src_port(src_port);
                }
                if let Some(dest_port) = dest_port {
                    udp.set_dst_port(dest_port);
                }
                udp.fill_checksum(src_addr, dst_addr);
                Some(ProtocolState::Udp)
            }
            IpProtocol::Icmp => {
                let mut icmp = Icmpv4Packet::new_unchecked(ipv4.payload_mut());
                match icmp.msg_type() {
                    Icmpv4Message::DstUnreachable
                    | Icmpv4Message::Redirect
                    | Icmpv4Message::TimeExceeded
                    | Icmpv4Message::ParamProblem => {
                        let mut nested_ipv4 = Ipv4Packet::new_unchecked(icmp.data_mut());
                        // flipped source and destination arguments, as ICMP needs it
                        let result = Self::translate_packet(
                            &mut nested_ipv4,
                            dest,
                            src,
                            dest_port,
                            src_port,
                        );

                        if result.is_some() {
                            icmp.fill_checksum();
                        }
                        result
                    }
                    Icmpv4Message::EchoRequest
                    | Icmpv4Message::EchoReply
                    | Icmpv4Message::Timestamp
                    | Icmpv4Message::TimestampReply => {
                        if let Some(new_id) = src_port.or(dest_port) {
                            icmp.set_echo_ident(new_id);
                        }
                        icmp.fill_checksum();
                        Some(ProtocolState::Icmp)
                    }
                    _ => None,
                }
            }
            _ => None,
        };

        if new_state.is_some() {
            ipv4.fill_checksum();
        }
        new_state
    }
}
