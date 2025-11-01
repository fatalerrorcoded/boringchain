use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub client: ConfigClient,
    pub server: ConfigServer,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigClient {
    #[serde_as(as = "Base64")]
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub address: Ipv4Addr,

    #[serde_as(as = "Base64")]
    pub peer_public_key: [u8; 32],
    #[serde_as(as = "Option<Base64>")]
    pub peer_preshared_key: Option<[u8; 32]>,
    pub peer_endpoint: Option<SocketAddr>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigServer {
    #[serde_as(as = "Base64")]
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub address: Ipv4Addr,

    #[serde(default, rename = "peer")]
    pub peers: Vec<ConfigServerPeer>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigServerPeer {
    #[serde_as(as = "Base64")]
    pub public_key: [u8; 32],
    #[serde_as(as = "Option<Base64>")]
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub peer_address: Ipv4Addr,
}
