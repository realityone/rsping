extern crate pnet;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;

pub mod error;
mod ping;

use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;

use pnet::datalink;

fn main() {
    let source_ip = Ipv4Addr::from_str("192.168.10.165").unwrap();
    let source_mac = MacAddr::from_str("98:01:a7:8d:84:39").unwrap();
    let target_ip = Ipv4Addr::from_str("192.168.10.1").unwrap();
    let target_mac = MacAddr::from_str("FF:FF:FF:FF:FF:FF").unwrap();

    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().filter(|iface| iface.name == "en0").next().unwrap();
    ping::arp::ping(interface, 1, 5, source_ip, source_mac, target_ip, target_mac).unwrap();
}
