use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use etherparse::{LaxNetSlice, LaxSlicedPacket, SlicedPacket, TransportSlice};
use tokio::time::{Duration, Instant};

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

    pub fn translate_outward(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let packet = SlicedPacket::from_ip(data).ok()?;
        let net_slice = packet.net?;
        let ip_slice = net_slice.ipv4_ref()?;
        let ip_source = ip_slice.header().source_addr();

        let key = self.get_outward_key(packet.transport?, ip_source)?;
        let entry = self.outward.get(&key);

        Some(Vec::new())
    }

    pub fn translate_inward(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let packet = SlicedPacket::from_ip(data).ok()?;
        let net_slice = packet.net?;
        let ip_slice = net_slice.ipv4_ref()?;
        let ip_source = ip_slice.header().source_addr();

        let key = self.get_inward_key(packet.transport?, ip_source)?;
        let entry = self.inward.get(&key)?; // drop incoming packet without corresponding nat entry

        Some(Vec::new())
    }

    fn get_inward_key(&self, transport: TransportSlice<'_>, source: Ipv4Addr) -> Option<NatKey> {
        self.get_key(transport, source, false, false)
    }

    fn get_outward_key(&self, transport: TransportSlice<'_>, source: Ipv4Addr) -> Option<NatKey> {
        self.get_key(transport, source, true, true)
    }

    fn get_key(
        &self,
        transport: TransportSlice<'_>,
        source: Ipv4Addr,
        is_outward: bool,
        reversed: bool,
    ) -> Option<NatKey> {
        match transport {
            etherparse::TransportSlice::Tcp(tcp) => {
                let port = if reversed {
                    tcp.source_port()
                } else {
                    tcp.destination_port()
                };
                Some(NatKey::new(
                    Protocol::Tcp,
                    port,
                    is_outward.then_some(source),
                ))
            }
            etherparse::TransportSlice::Udp(udp) => {
                let port = if reversed {
                    udp.source_port()
                } else {
                    udp.destination_port()
                };
                // if outward, provide originator - ensures correct NAT operation
                // if inward, do not provide originator - this turns NAT from symmetric to full cone
                Some(NatKey::new(
                    Protocol::Udp,
                    port,
                    is_outward.then_some(source),
                ))
            }
            etherparse::TransportSlice::Icmpv4(icmp) => match icmp.icmp_type() {
                etherparse::Icmpv4Type::Unknown { .. } => None,
                etherparse::Icmpv4Type::DestinationUnreachable(_)
                | etherparse::Icmpv4Type::Redirect(_)
                | etherparse::Icmpv4Type::TimeExceeded(_)
                | etherparse::Icmpv4Type::ParameterProblem(_) => {
                    let inner_packet = LaxSlicedPacket::from_ip(icmp.payload()).ok()?;
                    let net_slice = inner_packet.net?;
                    let LaxNetSlice::Ipv4(ip_slice) = net_slice else {
                        return None;
                    };

                    let original_destination = ip_slice.header().destination_addr();
                    self.get_key(
                        inner_packet.transport?,
                        original_destination,
                        is_outward,
                        !reversed,
                    )
                }
                etherparse::Icmpv4Type::EchoRequest(echo)
                | etherparse::Icmpv4Type::EchoReply(echo) => Some(NatKey::new(
                    Protocol::Icmp,
                    echo.id,
                    is_outward.then_some(source),
                )),
                etherparse::Icmpv4Type::TimestampRequest(timestamp)
                | etherparse::Icmpv4Type::TimestampReply(timestamp) => Some(NatKey::new(
                    Protocol::Icmp,
                    timestamp.id,
                    is_outward.then_some(source),
                )),
            },
            etherparse::TransportSlice::Icmpv6(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone)]
enum ProtocolState {
    TcpSynSent,
    TcpSynReceived,
    TcpEstablished,
    TcpClose,
    Udp,
    UdpStream,
    Icmp,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NatKey {
    protocol: Protocol,
    port: u16,
    originator: Option<Ipv4Addr>,
}

impl NatKey {
    pub fn new(protocol: Protocol, port: u16, originator: Option<Ipv4Addr>) -> NatKey {
        NatKey {
            protocol,
            port,
            originator,
        }
    }
}

#[derive(Debug, Clone)]
struct NatEntry {
    protocol: Protocol,
    protocol_state: ProtocolState,
    external_port: u16,
    external_peer: Option<Ipv4Addr>,
    internal: SocketAddrV4,
    last_activity: Instant,
}

impl NatEntry {
    pub fn timeout_at(&self) -> Instant {
        let timeout = match self.protocol_state {
            ProtocolState::TcpSynSent => Duration::from_secs(5),
            ProtocolState::TcpSynReceived => Duration::from_secs(5),
            ProtocolState::TcpEstablished => Duration::from_hours(2),
            ProtocolState::TcpClose => Duration::from_secs(10),
            ProtocolState::Udp => Duration::from_secs(30),
            ProtocolState::UdpStream => Duration::from_mins(2),
            ProtocolState::Icmp => Duration::from_secs(10),
        };

        self.last_activity + timeout
    }
}
