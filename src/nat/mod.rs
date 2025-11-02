use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use bitflags::bitflags_match;
use ingot::icmp::{IcmpV4Mut, IcmpV4Ref, IcmpV4Type, ValidIcmpV4};
use ingot::ip::{IpProtocol, Ipv4Mut, Ipv4Ref, ValidIpv4};
use ingot::tcp::{TcpFlags, TcpMut, TcpRef, ValidTcp};
use ingot::types::HeaderParse;
use ingot::udp::{UdpMut, UdpRef, ValidUdp};
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
        let (mut ipv4, _, rest) = ValidIpv4::parse(data).ok()?;

        let ip_source = ipv4.source().into();
        let key = Self::get_outward_key(ipv4.protocol(), rest, ip_source)?;
        let entry = self.outward.get_mut(&key);

        if let Some(entry) = entry {
            let new_state = Self::translate_packet(
                &mut ipv4,
                rest,
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
            rest,
            Some(self.public_address),
            None,
            Some(external_port),
            None
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
        let (mut ipv4, _, rest) = ValidIpv4::parse(data).ok()?;
        let ip_source = ipv4.source().into();

        let key = Self::get_inward_key(ipv4.protocol(), rest, ip_source)?;
        let entry = self.inward.get_mut(&key)?; // drop incoming packet without corresponding nat entry

        let new_state = Self::translate_packet(
            &mut ipv4,
            rest,
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

    fn get_inward_key(hint: IpProtocol, rest: &[u8], source: Ipv4Addr) -> Option<NatKey> {
        Self::get_key(hint, rest, source, false, false)
    }

    fn get_outward_key(hint: IpProtocol, rest: &[u8], source: Ipv4Addr) -> Option<NatKey> {
        Self::get_key(hint, rest, source, true, true)
    }

    fn get_key(
        hint: IpProtocol,
        rest: &[u8],
        source: Ipv4Addr,
        is_outward: bool,
        reversed: bool,
    ) -> Option<NatKey> {
        match hint {
            IpProtocol::TCP => {
                let (tcp, ..) = ValidTcp::parse(rest).ok()?;
                let port = if reversed {
                    tcp.source()
                } else {
                    tcp.destination()
                };
                Some(NatKey::new(
                    Protocol::Tcp,
                    port,
                    is_outward.then_some(source),
                ))
            }
            IpProtocol::UDP => {
                let (udp, ..) = ValidUdp::parse(rest).ok()?;
                let port = if reversed {
                    udp.source()
                } else {
                    udp.destination()
                };
                // if outward, provide originator - ensures correct NAT operation
                // if inward, do not provide originator - this turns NAT from symmetric to full cone
                Some(NatKey::new(
                    Protocol::Udp,
                    port,
                    is_outward.then_some(source),
                ))
            }
            IpProtocol::ICMP => {
                let (icmp, _, rest_icmp) = ValidIcmpV4::parse(rest).ok()?;
                match icmp.ty() {
                    ty if ty.payload_is_packet() => {
                        let (ipv4, _, rest_ipv4) = ValidIpv4::parse(rest_icmp).ok()?;
                        let original_destination = ipv4.destination().into();
                        Self::get_key(
                            ipv4.protocol(),
                            rest_ipv4,
                            original_destination,
                            is_outward,
                            !reversed,
                        )
                    }
                    IcmpV4Type::ECHO_REQUEST
                    | IcmpV4Type::ECHO_REPLY
                    | IcmpV4Type::TIMESTAMP
                    | IcmpV4Type::TIMESTAMP_REPLY => {
                        let id_slice = &icmp.rest_of_hdr()[0..2];
                        let id = u16::from_be_bytes(id_slice.try_into().unwrap());
                        Some(NatKey::new(
                            Protocol::Icmp,
                            id,
                            is_outward.then_some(source),
                        ))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn get_free_external_port(&mut self, protocol: Protocol, wanted_port: u16) -> Option<u16> {
        if !self.inward.contains_key(&NatKey::new(protocol, wanted_port, None)) {
            return Some(wanted_port);
        }

        let starting_port: u16 = rand::random();
        let mut current_port = starting_port.wrapping_add(1);
        while current_port != starting_port {
            if current_port == 0 {
                continue;
            }

            if !self.inward.contains_key(&NatKey::new(protocol, wanted_port, None)) {
                return Some(wanted_port);
            }

            current_port = current_port.wrapping_add(1);
        }

        None
    }

    fn translate_packet(
        ipv4: &mut ValidIpv4<&mut [u8]>,
        rest: &mut [u8],
        src: Option<Ipv4Addr>,
        dest: Option<Ipv4Addr>,
        src_port: Option<u16>,
        dest_port: Option<u16>,
    ) -> Option<ProtocolState> {
        if let Some(src) = src {
            ipv4.set_source(src.into());
        }

        if let Some(dest) = dest {
            ipv4.set_destination(dest.into());
        }

        match ipv4.protocol() {
            IpProtocol::TCP => {
                let (mut tcp, ..) = ValidTcp::parse(rest).ok()?;
                if let Some(src_port) = src_port {
                    tcp.set_source(src_port);
                }
                if let Some(dest_port) = dest_port {
                    tcp.set_destination(dest_port);
                }

                let flags = tcp.flags();
                bitflags_match!(flags, {
                    TcpFlags::SYN => ProtocolState::TcpSynSent,
                    TcpFlags::SYN | TcpFlags::ACK => ProtocolState::TcpSynReceived,
                    TcpFlags::FIN => ProtocolState::TcpClosing,
                    TcpFlags::FIN | TcpFlags::ACK => ProtocolState::TcpClosing,
                    TcpFlags::RST => ProtocolState::TcpClosed,
                    _ => ProtocolState::TcpEstablished,
                });
                Some(ProtocolState::TcpEstablished)
            }
            IpProtocol::UDP => {
                let (mut udp, ..) = ValidUdp::parse(rest).ok()?;
                if let Some(src_port) = src_port {
                    udp.set_source(src_port);
                }
                if let Some(dest_port) = dest_port {
                    udp.set_destination(dest_port);
                }
                Some(ProtocolState::Udp)
            }
            IpProtocol::ICMP => {
                let (mut icmp, _, rest_icmp) = ValidIcmpV4::parse(rest).ok()?;
                match icmp.ty() {
                    ty if ty.payload_is_packet() => {
                        let (mut nested_ipv4, _, rest_nested) = ValidIpv4::parse(rest_icmp).ok()?;
                        // flipped source and destination arguments, as ICMP needs it
                        Self::translate_packet(
                            &mut nested_ipv4,
                            rest_nested,
                            dest,
                            src,
                            dest_port,
                            src_port,
                        )
                    }
                    IcmpV4Type::ECHO_REQUEST
                    | IcmpV4Type::ECHO_REPLY
                    | IcmpV4Type::TIMESTAMP
                    | IcmpV4Type::TIMESTAMP_REPLY => {
                        if let Some(new_id) = src_port.or(dest_port) {
                            let id_slice = u16::to_be_bytes(new_id);
                            let rest_of_hdr = icmp.rest_of_hdr_mut();
                            rest_of_hdr[0..2].copy_from_slice(&id_slice);
                        }
                        Some(ProtocolState::Icmp)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}
