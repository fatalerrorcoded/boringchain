use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use smoltcp::wire::{
    IPV4_HEADER_LEN, Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Packet, TCP_HEADER_LEN,
    TcpPacket, UDP_HEADER_LEN, UdpPacket,
};
use tokio::time::Instant;

mod types;
pub use types::Protocol;
use types::*;

#[cfg(test)]
mod test;

pub struct AddressTranslator {
    public_address: Ipv4Addr,
    port_forward: HashMap<(Protocol, u16), Ipv4Addr>,

    inward: HashMap<NatKey, NatEntry>,
    outward: HashMap<NatKey, NatEntry>,
}

impl AddressTranslator {
    pub fn new(public_address: Ipv4Addr, port_forward: HashMap<(Protocol, u16), Ipv4Addr>) -> Self {
        AddressTranslator {
            public_address,
            port_forward,
            inward: HashMap::new(),
            outward: HashMap::new(),
        }
    }

    pub fn translate_outward(&mut self, data: &mut [u8]) -> Option<()> {
        let mut ipv4 = Ipv4Packet::new_checked(data).ok()?;
        let ip_source = ipv4.src_addr();

        let key = Self::get_outward_key(ipv4.next_header(), ipv4.payload_mut(), ip_source)?;
        if let Some(forward_entry) = self.port_forward.get(&(key.protocol, key.port))
            && *forward_entry == ip_source
        {
            Self::translate_packet(&mut ipv4, Some(self.public_address), None, None, None)?;
            return Some(());
        }

        let entry = self.outward.get_mut(&key);
        if let Some(entry) = entry
            && !entry.is_stale(Instant::now())
        {
            let translate_state = Self::translate_packet(
                &mut ipv4,
                Some(self.public_address),
                None,
                Some(entry.external_port),
                None,
            )?;

            entry.protocol_state.update_state(translate_state);
            entry.last_activity = Instant::now();
            self.inward.insert(entry.to_inward_key(), entry.clone());
            return Some(());
        }

        let external_port = self.get_free_external_port(key.protocol, key.port)?;
        let translate_state = Self::translate_packet(
            &mut ipv4,
            Some(self.public_address),
            None,
            Some(external_port),
            None,
        )?;

        let entry = NatEntry {
            protocol: key.protocol,
            protocol_state: ProtocolState::new(translate_state)?,
            external_port,
            internal: SocketAddrV4::new(ip_source, key.port),
            last_activity: Instant::now(),
        };

        println!(
            "Inserting NAT entry {:?} [{}] -> [{}]",
            entry.protocol, entry.internal, entry.external_port
        );

        self.inward.insert(entry.to_inward_key(), entry.clone());
        self.outward.insert(entry.to_outward_key(), entry);
        Some(())
    }

    pub fn translate_inward(&mut self, data: &mut [u8]) -> Option<()> {
        let mut ipv4 = Ipv4Packet::new_checked(data).ok()?;
        let ip_source = ipv4.src_addr();

        let key = Self::get_inward_key(ipv4.next_header(), ipv4.payload_mut(), ip_source)?;
        if let Some(forward_entry) = self.port_forward.get(&(key.protocol, key.port)) {
            Self::translate_packet(&mut ipv4, None, Some(*forward_entry), None, None)?;
            return Some(());
        }

        let entry = self.inward.get_mut(&key)?; // drop incoming packet without corresponding nat entry
        if entry.is_stale(Instant::now()) {
            return None;
        }

        let translate_state = Self::translate_packet(
            &mut ipv4,
            None,
            Some(*entry.internal.ip()),
            None,
            Some(entry.internal.port()),
        )?;

        entry.protocol_state.update_state(translate_state);
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
                        // manually slice as this is a partial payload
                        let inner_payload = &icmp_payload[IPV4_HEADER_LEN..];
                        Self::get_key(
                            ipv4.next_header(),
                            inner_payload,
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
        let now = Instant::now();
        while current_port != starting_port {
            if current_port == 0 {
                continue;
            }

            let inward_key = NatKey::new(protocol, wanted_port, None);
            let (outward_key, is_stale) = match self.inward.get(&inward_key) {
                Some(entry) => (entry.to_outward_key(), entry.is_stale(now)),
                None => return Some(wanted_port),
            };

            if is_stale {
                self.inward.remove(&inward_key);
                self.outward.remove(&outward_key);
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
    ) -> Option<TranslateState> {
        let old_src = ipv4.src_addr();
        if let Some(src) = src {
            ipv4.set_src_addr(src);
        }

        let old_dst = ipv4.dst_addr();
        if let Some(dest) = dest {
            ipv4.set_dst_addr(dest);
        }

        let new_src = ipv4.src_addr();
        let new_dst = ipv4.dst_addr();
        // work around payload_mut() panicking if the packet is too short
        let original_len = ipv4.total_len();
        ipv4.set_total_len(ipv4.as_ref().len() as u16);

        let new_state = match ipv4.next_header() {
            IpProtocol::Tcp => {
                let mut tcp = TcpPacket::new_unchecked(ipv4.payload_mut());
                if let Some(src_port) = src_port {
                    tcp.set_checksum(Self::new_checksum_for_u16(
                        tcp.checksum(),
                        tcp.src_port(),
                        src_port,
                    ));
                    tcp.set_src_port(src_port);
                }
                if let Some(dest_port) = dest_port {
                    tcp.set_checksum(Self::new_checksum_for_u16(
                        tcp.checksum(),
                        tcp.dst_port(),
                        dest_port,
                    ));
                    tcp.set_dst_port(dest_port);
                }

                tcp.set_checksum(Self::new_checksum_for_addr(tcp.checksum(), old_src, new_src));
                tcp.set_checksum(Self::new_checksum_for_addr(tcp.checksum(), old_dst, new_dst));
                match tcp {
                    _ if tcp.rst() => Some(TranslateState::TcpRst),
                    _ if tcp.fin() && tcp.ack() => Some(TranslateState::TcpFinAck),
                    _ if tcp.fin() => Some(TranslateState::TcpFin),
                    _ if tcp.syn() && tcp.ack() => Some(TranslateState::TcpSynAck),
                    _ if tcp.syn() => Some(TranslateState::TcpSyn),
                    _ if tcp.ack() => Some(TranslateState::TcpAck),
                    _ => Some(TranslateState::TcpBase),
                }
            }
            IpProtocol::Udp => {
                let mut udp = UdpPacket::new_unchecked(ipv4.payload_mut());
                if let Some(src_port) = src_port {
                    udp.set_checksum(Self::new_checksum_for_u16(
                        udp.checksum(),
                        udp.src_port(),
                        src_port,
                    ));
                    udp.set_src_port(src_port);
                }
                if let Some(dest_port) = dest_port {
                    udp.set_checksum(Self::new_checksum_for_u16(
                        udp.checksum(),
                        udp.dst_port(),
                        dest_port,
                    ));
                    udp.set_dst_port(dest_port);
                }

                udp.set_checksum(Self::new_checksum_for_addr(udp.checksum(), old_src, new_src));
                udp.set_checksum(Self::new_checksum_for_addr(udp.checksum(), old_dst, new_dst));
                Some(TranslateState::Udp)
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
                        Some(TranslateState::Icmp)
                    }
                    _ => None,
                }
            }
            _ => None,
        };

        // reset original length
        ipv4.set_total_len(original_len);
        if new_state.is_some() {
            ipv4.fill_checksum();
        }
        new_state
    }

    fn new_checksum_for_addr(checksum: u16, old_value: Ipv4Addr, new_value: Ipv4Addr) -> u16 {
        let old_value_high = (old_value.to_bits() >> 16) as u16;
        let old_value_low = (old_value.to_bits() & 0xFFFF) as u16;

        let new_value_high = (new_value.to_bits() >> 16) as u16;
        let new_value_low = (new_value.to_bits() & 0xFFFF) as u16;

        let checksum = Self::new_checksum_for_u16(checksum, old_value_low, new_value_low);
        Self::new_checksum_for_u16(checksum, old_value_high, new_value_high)
    }

    fn new_checksum_for_u16(checksum: u16, old_value: u16, new_value: u16) -> u16 {
        let checksum = (!checksum as u32)
            .wrapping_add(!old_value as u32)
            .wrapping_add(new_value as u32);

        // fold 32-bit back into 16 bits
        let sum = (checksum & 0xFFFF) + (checksum >> 16);
        let sum = (sum & 0xFFFF) + (sum >> 16);
        !(sum as u16)
    }
}
