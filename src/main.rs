use std::fs;

pub mod config;
pub mod tunnel;

use config::Config;
use futures::future::join_all;

#[tokio::main]
async fn main() {
    let config_data = fs::read("./boringchain.toml").expect("No boringchain.toml config");
    let config: Config = toml::from_slice(&config_data).expect("Invalid config");

    let server_task = tunnel::server::start_server_task(config.server);

    join_all([server_task]).await;
}
