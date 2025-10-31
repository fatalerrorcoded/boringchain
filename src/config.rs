use std::net::{Ipv4Addr, SocketAddrV4};

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    client: ConfigClient,
    server: ConfigServer,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigClient {
    #[serde_as(as = "Base64")]
    private_key: [u8; 32],
    listen_port: u16,
    address: Ipv4Addr,

    #[serde_as(as = "Base64")]
    peer_public_key: [u8; 32],
    peer_endpoint: SocketAddrV4,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigServer {
    #[serde_as(as = "Base64")]
    private_key: [u8; 32],
    listen_port: u16,
    address: Ipv4Addr,

    #[serde(default, rename = "peer")]
    peers: Vec<ConfigServerPeer>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigServerPeer {
    #[serde_as(as = "Base64")]
    public_key: [u8; 32],
    #[serde_as(as = "Option<Base64>")]
    preshared_key: Option<[u8; 32]>,
    peer_address: Ipv4Addr,
}
