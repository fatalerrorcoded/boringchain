use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy)]
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

impl ProtocolState {
    pub fn update_state(&mut self, new_state: Self) {
        *self = match (*self, new_state) {
            (ProtocolState::TcpSynSent, ProtocolState::TcpSynReceived) => new_state,
            (ProtocolState::TcpSynReceived, ProtocolState::TcpEstablished) => new_state,
            // any move from established to closing is allowed
            (
                ProtocolState::TcpSynSent
                | ProtocolState::TcpSynReceived
                | ProtocolState::TcpEstablished,
                ProtocolState::TcpClosing | ProtocolState::TcpClosed,
            ) => new_state,
            // an ack received when closing means that we have finished closing
            (ProtocolState::TcpClosing, ProtocolState::TcpEstablished) => ProtocolState::TcpClosed,
            // a second UDP packet means we have likely established a stream
            (ProtocolState::Udp, ProtocolState::Udp) => ProtocolState::UdpStream,
            _ => *self,
        };
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NatKey {
    pub protocol: Protocol,
    pub port: u16,
    pub originator: Option<Ipv4Addr>,
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
    pub protocol: Protocol,
    pub protocol_state: ProtocolState,
    pub external_port: u16,
    pub internal: SocketAddrV4,
    pub last_activity: Instant,
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
    pub fn is_stale(&self, now: Instant) -> bool {
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

        now > (self.last_activity + timeout)
    }
}
