extern crate pnet;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;

pub mod error;
mod ping;
mod utils;

use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn main() {
    let source_ip = Ipv4Addr::from_str("10.8.0.31").unwrap();
    let source_mac = MacAddr::from_str("98:01:a7:8d:84:35").unwrap();
    let target_ip = Ipv4Addr::from_str("10.8.0.1").unwrap();
    let target_mac = MacAddr::from_str("FF:FF:FF:FF:FF:FF").unwrap();

    let ifname = "en0";
    let iface = utils::find_interface(ifname).expect(format!("interface {} does not exist", ifname).as_str());
    let arpping = ping::arp::ARPPing::new(iface, 1, 30, source_ip, source_mac, target_ip, target_mac);
    for r in arpping.into_iter() {
        println!("{:?}", r);
    }
}
