use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone)]
pub enum ProtocolState {
    TcpSynSent,
    TcpSynReceived,
    TcpEstablished,
    TcpClosing,
    TcpClosed,
    Udp,
    UdpStream,
    Icmp,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NatKey {
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
pub struct NatEntry {
    protocol: Protocol,
    protocol_state: ProtocolState,
    external_port: u16,
    internal: SocketAddrV4,
    last_activity: Instant,
}

impl NatEntry {
    pub fn to_inward_key(&self) -> NatKey {
        NatKey {
            protocol: self.protocol,
            port: self.external_port,
            originator: None,
        }
    }

    pub fn to_outward_key(&self) -> NatKey {
        NatKey {
            protocol: self.protocol,
            port: self.internal.port(),
            originator: Some(*self.internal.ip()),
        }
    }
}

impl NatEntry {
    pub fn timeout_at(&self) -> Instant {
        let timeout = match self.protocol_state {
            ProtocolState::TcpSynSent => Duration::from_secs(5),
            ProtocolState::TcpSynReceived => Duration::from_secs(5),
            ProtocolState::TcpEstablished => Duration::from_hours(2),
            ProtocolState::TcpClosing => Duration::from_secs(10),
            ProtocolState::TcpClosed => Duration::from_secs(10),
            ProtocolState::Udp => Duration::from_secs(30),
            ProtocolState::UdpStream => Duration::from_mins(2),
            ProtocolState::Icmp => Duration::from_secs(10),
        };

        self.last_activity + timeout
    }
}
