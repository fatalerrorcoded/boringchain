use std::fs;

pub mod config;

use config::Config;

fn main() {
    let config_data = fs::read("./boringchain.toml").expect("No boringchain.toml config");
    let config: Config = toml::from_slice(&config_data).expect("Invalid config");
    println!("{:#?}", config);
}
