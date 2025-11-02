use std::net::Ipv4Addr;

use ingot::icmp::{IcmpV4Ref, IcmpV4Type, ValidIcmpV4};
use ingot::ip::{IpProtocol, Ipv4Mut, Ipv4Ref, ValidIpv4};
use ingot::types::HeaderParse;

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

pub async fn process_local(
    data: &mut [u8],
    address: Ipv4Addr,
) -> ProcessLocalResult {
    let Ok((ipv4, _, rest)) = ValidIpv4::parse(data) else {
        return ProcessLocalResult::NotLocal;
    };

    if Ipv4Addr::from(ipv4.destination()) != address {
        return ProcessLocalResult::NotLocal;
    }

    match ipv4.protocol() {
        IpProtocol::ICMP => {
            process_local_icmp(ipv4, rest).await.into()
        }
        _ => ProcessLocalResult::Done,
    }
}

async fn process_local_icmp(
    mut ipv4: ValidIpv4<&mut [u8]>,
    rest: &mut [u8],
) -> Option<()> {
    let (icmp, _, _) = ValidIcmpV4::parse(rest).ok()?;
    if icmp.ty() != IcmpV4Type::ECHO_REQUEST {
        return None;
    };

    let original_sender = ipv4.source();
    ipv4.set_source(ipv4.destination());
    ipv4.set_destination(original_sender);
    Some(())
}
