use std::collections::HashMap;
use std::net::Ipv4Addr;

use ingot::icmp::{IcmpV4Ref, IcmpV4Type, ValidIcmpV4};
use ingot::ip::{IpProtocol, Ipv4Ref, ValidIpv4};
use ingot::tcp::{TcpRef, ValidTcp};
use ingot::types::HeaderParse;
use ingot::udp::{UdpRef, ValidUdp};

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
        let entry = self.outward.get(&key);

        Some(())
    }

    pub fn translate_inward(&mut self, data: &mut [u8]) -> Option<()> {
        let (mut ipv4, _, rest) = ValidIpv4::parse(data).ok()?;
        let ip_source = ipv4.source().into();

        let key = Self::get_inward_key(ipv4.protocol(), rest, ip_source)?;
        let entry = self.inward.get(&key)?; // drop incoming packet without corresponding nat entry

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
}
