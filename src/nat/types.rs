use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy)]
pub enum TranslateState {
    TcpBase,
    TcpAck,
    TcpSyn,
    TcpSynAck,
    TcpFin,
    TcpFinAck,
    TcpRst,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy)]
pub enum ProtocolState {
    TcpSynSent,
    TcpSynReceived,
    TcpEstablished,
    TcpFinWait,
    TcpTimeWait,
    TcpClosed,
    Udp,
    UdpStream,
    Icmp,
}

impl ProtocolState {
    pub fn new(state: TranslateState) -> Option<Self> {
        match state {
            TranslateState::TcpBase => None,
            TranslateState::TcpAck => None,
            TranslateState::TcpSyn => Some(ProtocolState::TcpSynSent),
            TranslateState::TcpSynAck => Some(ProtocolState::TcpSynReceived),
            TranslateState::TcpFin => None,
            TranslateState::TcpFinAck => None,
            TranslateState::TcpRst => None,
            TranslateState::Udp => Some(ProtocolState::Udp),
            TranslateState::Icmp => Some(ProtocolState::Icmp),
        }
    }

    pub fn update_state(&mut self, translate_state: TranslateState) {
        use ProtocolState as PS;
        use TranslateState as TS;
        let old = self.clone();
        *self = match (*self, translate_state) {
            (PS::TcpSynSent, TS::TcpSynAck) => PS::TcpSynReceived,
            (PS::TcpSynReceived, TS::TcpAck) => PS::TcpEstablished,
            // any move from established to FinWait and TimeWait is allowed
            (PS::TcpSynSent | PS::TcpSynReceived | PS::TcpEstablished, TS::TcpFin) => {
                PS::TcpFinWait
            }
            (
                PS::TcpSynSent | PS::TcpSynReceived | PS::TcpEstablished | PS::TcpFinWait,
                TS::TcpFinAck,
            ) => PS::TcpTimeWait,
            // an ack received when in TimeWait means that we have finished closing
            (PS::TcpTimeWait, TS::TcpAck) => PS::TcpClosed,
            // allow moving from closed back into TimeWait if we see another FinAck
            (PS::TcpClosed, TS::TcpFinAck) => PS::TcpTimeWait,
            // allow resetting from closed state
            // HACK: this should only be for TcpSynSent, but that can cause issues right now because
            //       we don't track TCP connections per ip:port, only per port
            (PS::TcpClosed, TS::TcpBase | TS::TcpAck) => PS::TcpEstablished,
            // a second UDP packet means we have likely established a stream
            (PS::Udp, TS::Udp) => PS::UdpStream,
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
            // HACK: closing states are intentionally longer because of how the TCP connection tracking works
            ProtocolState::TcpFinWait => Duration::from_mins(1),
            ProtocolState::TcpTimeWait => Duration::from_mins(1),
            ProtocolState::TcpClosed => Duration::from_mins(1),
            ProtocolState::Udp => Duration::from_secs(30),
            ProtocolState::UdpStream => Duration::from_mins(2),
            ProtocolState::Icmp => Duration::from_secs(10),
        };

        now > (self.last_activity + timeout)
    }
}
