use pnet::datalink::{self, NetworkInterface};

pub fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().filter(|iface| iface.name == name).next()
}