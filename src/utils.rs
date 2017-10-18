use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use ipnetwork::IpNetwork;
use pnet::datalink::{self, NetworkInterface};
use pnet::util::MacAddr;

pub fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().filter(|iface| iface.name == name).next()
}

pub fn first_ipv4_address(interface: &NetworkInterface) -> Option<Ipv4Addr> {
    interface.ips.iter().filter(|ip| ip.is_ipv4()).next().map(|ip| match ip {
                                                                  &IpNetwork::V4(ip) => ip.ip(),
                                                                  _ => unreachable!(),
                                                              })
}

pub fn interface_validator(name: String) -> Result<(), String> {
    match find_interface(&name) {
        None => Err(format!("interface {} does not exist", name)),
        Some(_) => Ok(()),
    }
}

pub fn ip_address_validator(value: String) -> Result<(), String> {
    match Ipv4Addr::from_str(&value) {
        Err(_) => Err(format!("bad IP address: {}", value)),
        Ok(_) => Ok(()),
    }
}

pub fn mac_address_validator(value: String) -> Result<(), String> {
    match MacAddr::from_str(&value) {
        Err(_) => Err(format!("bad MAC address: {}", value)),
        Ok(_) => Ok(()),
    }
}

pub fn num_validator(value: String) -> Result<(), String> {
    match u64::from_str(&value) {
        Err(_) => Err(format!("value {} is not a number", value)),
        Ok(_) => Ok(()),
    }
}

pub fn total_millis(duration: Duration) -> f64 {
    (duration.as_secs() * 1000) as f64 + (duration.subsec_nanos() as f64 / 1000000f64) as f64
}