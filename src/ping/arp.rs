use std::net::Ipv4Addr;

use pnet::datalink::{self, Channel, Config, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use error::*;

lazy_static!{
    static ref MINIMUM_BUFFER_SIZE: usize = MutableArpPacket::minimum_packet_size() + MutableEthernetPacket::minimum_packet_size();
}

pub fn arp_buffer() -> Vec<u8> {
    vec![0u8; *MINIMUM_BUFFER_SIZE]
}

// Build an ethernet packet for sending ARP request
pub fn build_ethernet<'a>(buffer: &'a mut Vec<u8>, source_ip: Ipv4Addr, source_mac: MacAddr, target_ip: Ipv4Addr,
                          target_mac: MacAddr)
                          -> Result<MutableEthernetPacket<'a>> {
    let mut ethernet_packet = {
        let mut ethernet_packet = MutableEthernetPacket::new(buffer).ok_or(ErrorKind::BuildPacketError)?;

        ethernet_packet.set_destination(target_mac);
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);
        ethernet_packet
    };

    let mut arp_buffer = vec![0u8; MutableArpPacket::minimum_packet_size()];
    let arp_req = {
        let mut arp_req = MutableArpPacket::new(&mut arp_buffer).ok_or(ErrorKind::BuildPacketError)?;

        arp_req.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_req.set_protocol_type(EtherTypes::Ipv4);
        // 6 bytes for mac address
        arp_req.set_hw_addr_len(6);
        // 4 bytes for ip address
        arp_req.set_proto_addr_len(4);
        arp_req.set_operation(ArpOperations::Request);
        arp_req.set_sender_hw_addr(source_mac);
        arp_req.set_sender_proto_addr(source_ip);
        arp_req.set_target_hw_addr(target_mac);
        arp_req.set_target_proto_addr(target_ip);
        arp_req
    };

    // set the payload
    ethernet_packet.set_payload(arp_req.packet());
    Ok(ethernet_packet)
}

pub fn from_ethernet<'a>(ethernet_packet: &'a EthernetPacket) -> Result<ArpPacket<'a>> {
    if ethernet_packet.get_ethertype() != EtherTypes::Arp {
        return Err(ErrorKind::ParsePacketError.into());
    }

    Ok(ArpPacket::new(ethernet_packet.payload()).ok_or(ErrorKind::ParsePacketError)?)
}

pub fn ping_once(source_ip: Ipv4Addr, source_mac: MacAddr, target_ip: Ipv4Addr, target_mac: MacAddr,
                 interface: NetworkInterface, channel: Channel)
                 -> Result<()> {
    let (mut tx, rx) = match channel {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => unreachable!(),
    };

    let mut buffer = arp_buffer();
    let arp_ether = build_ethernet(&mut buffer, source_ip, source_mac, target_ip, target_mac)?;

    // record arp request send time
    tx.send_to(&arp_ether.to_immutable(), None).ok_or(ErrorKind::SendPacketError)??;

    // arp response not received in *** than consider as timeout

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_arp() {
        let source_ip = Ipv4Addr::from_str("192.168.1.2").unwrap();
        let source_mac = MacAddr::from_str("00:0C:29:83:8C:20").unwrap();
        let target_ip = Ipv4Addr::from_str("192.168.1.3").unwrap();
        let target_mac = MacAddr::from_str("00:0C:29:24:20:6F").unwrap();

        let mut buffer = arp_buffer();

        let arp_ether = build_ethernet(&mut buffer, source_ip, source_mac, target_ip, target_mac).unwrap();
        let arp_ether2 = arp_ether.to_immutable();
        let parsed = from_ethernet(&arp_ether2).unwrap();

        assert_eq!(parsed.get_sender_proto_addr(), source_ip);
        assert_eq!(parsed.get_sender_hw_addr(), source_mac);
        assert_eq!(parsed.get_target_proto_addr(), target_ip);
        assert_eq!(parsed.get_target_hw_addr(), target_mac);
    }
}
