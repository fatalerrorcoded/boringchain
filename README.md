# boringchain
An utility to chain a singular Wireguard client with a Wireguard server, completely in userspace.

Boringchain is most useful when connecting to a Wireguard VPN provider that only allows a single connection, when you want to share that connection among multiple devices. It does this by emulating a network router, performing NAT to allow for multiple clients to pose as boringchain itself, fully in userspace, bypassing the networking stack of Linux and thus its many pitfalls when attempting to create an isolated Wireguard stack.

## Usage
When launched, boringchain will attempt to load a `boringchain.toml` config file in the same directory, or the path to the config file can be specified when launching boringchain, such as `./boringchain path/to/boringchain.toml`.
