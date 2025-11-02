use std::net::Ipv4Addr;

use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Packet};

pub enum ProcessLocalResult {
    Done,
    WriteBack,
    NotLocal,
}

impl From<Option<()>> for ProcessLocalResult {
    fn from(value: Option<()>) -> Self {
        match value {
            Some(_) => ProcessLocalResult::WriteBack,
            None => ProcessLocalResult::Done,
        }
    }
}

pub async fn process_local(data: &mut [u8], address: Ipv4Addr) -> ProcessLocalResult {
    let Ok(ipv4) = Ipv4Packet::new_checked(data) else {
        return ProcessLocalResult::NotLocal;
    };

    if ipv4.dst_addr() != address {
        return ProcessLocalResult::NotLocal;
    }

    match ipv4.next_header() {
        IpProtocol::Icmp => process_local_icmp(ipv4).await.into(),
        _ => ProcessLocalResult::Done,
    }
}

async fn process_local_icmp(mut ipv4: Ipv4Packet<&mut [u8]>) -> Option<()> {
    let mut icmp = Icmpv4Packet::new_checked(ipv4.payload_mut()).ok()?;
    if icmp.msg_type() != Icmpv4Message::EchoRequest {
        return None;
    };

    icmp.set_msg_type(Icmpv4Message::EchoReply);
    icmp.fill_checksum();

    let original_src = ipv4.src_addr();
    ipv4.set_src_addr(ipv4.dst_addr());
    ipv4.set_dst_addr(original_src);
    ipv4.fill_checksum();
    Some(())
}
