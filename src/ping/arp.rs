use std::io;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use pnet::datalink::{self, Channel, Config, NetworkInterface};
use pnet::datalink::{EthernetDataLinkReceiver, EthernetDataLinkSender};
use pnet::packet::{FromPacket, Packet};
use pnet::packet::arp::{Arp, ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use super::PingResult;
use error::*;

lazy_static!{
    static ref MINIMUM_BUFFER_SIZE: usize = MutableArpPacket::minimum_packet_size() + MutableEthernetPacket::minimum_packet_size();
}

struct ARPPingCtx {
    times: u64,
    timeout: Duration,
    channel: (Box<EthernetDataLinkSender>, Box<EthernetDataLinkReceiver>),
}

pub struct ARPPing {
    interface: NetworkInterface,
    timeout: u64,
    count: u64,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    target_ip: Ipv4Addr,
    target_mac: MacAddr,

    ctx: Option<ARPPingCtx>,
}

impl ARPPing {
    pub fn new(interface: NetworkInterface, timeout: u64, count: u64, source_ip: Ipv4Addr, source_mac: MacAddr,
               target_ip: Ipv4Addr, target_mac: MacAddr)
               -> Self {
        ARPPing {
            interface,
            timeout,
            count,
            source_ip,
            source_mac,
            target_ip,
            target_mac,

            ctx: None,
        }
    }

    fn ethernet_buffer() -> Vec<u8> {
        vec![0u8; *MINIMUM_BUFFER_SIZE]
    }

    // Build an ethernet packet for sending ARP request
    fn build_ethernet<'a>(buffer: &'a mut Vec<u8>, source_ip: Ipv4Addr, source_mac: MacAddr, target_ip: Ipv4Addr,
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

    fn init_ping_context(&mut self) {
        let times = 0;
        let timeout = Duration::from_secs(self.timeout);

        let mut config = Config::default();
        config.read_timeout = Some(timeout);
        config.write_timeout = Some(timeout);

        let channel = match datalink::channel(&self.interface, config).expect("Failed to create datalink channel") {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => unreachable!(),
        };

        self.ctx = Some(ARPPingCtx {
                            times,
                            timeout,
                            channel,
                        });
    }
}

impl Iterator for ARPPing {
    type Item = PingResult<Arp>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ctx.is_none() {
            self.init_ping_context();
        }

        let ctx = self.ctx.as_mut().unwrap();

        let (ref mut tx, ref mut rx) = ctx.channel;

        let mut buffer = Self::ethernet_buffer();
        let arp_ether =
            Self::build_ethernet(&mut buffer, self.source_ip, self.source_mac, self.target_ip, self.target_mac)
                .expect("Failed to build ARP packet");

        if ctx.times > self.count {
            return None;
        }
        ctx.times += 1;

        let now = SystemTime::now();
        let mut rx_iter = rx.iter();
        match tx.send_to(&arp_ether.to_immutable(), None) {
            None => return Some(Err(ErrorKind::SendPacketError.into())),
            _ => {}
        };

        loop {
            let elapsed = now.elapsed().unwrap();
            if elapsed > ctx.timeout {
                return Some(Err(ErrorKind::PingTimeout.into()));
            }

            match rx_iter.next() {
                Ok(packet) => {
                    if (packet.get_ethertype() != EtherTypes::Arp) ||
                        (packet.get_destination() != self.interface.mac_address())
                    {
                        continue;
                    }

                    let arp = match Self::from_ethernet(&packet) {
                        Ok(arp) => arp,
                        Err(e) => return Some(Err(e)),
                    };
                    // is a suitable arp reply for we ask
                    if (arp.get_operation() != ArpOperations::Reply) ||
                        (arp.get_target_proto_addr() != self.source_ip) ||
                        (arp.get_target_hw_addr() != self.source_mac) ||
                        (arp.get_sender_proto_addr() != self.target_ip)
                    {
                        continue;
                    }

                    let elapsed = now.elapsed().unwrap();
                    return Some(Ok((arp.from_packet(), elapsed)));
                }
                Err(e) => {
                    match e.kind() {
                        io::ErrorKind::TimedOut => {
                            return Some(Err(ErrorKind::PingTimeout.into()));
                        }

                        _ => {
                            return Some(Err(e.into()));
                        }
                    }
                }
            };
        }
    }
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

        let mut buffer = ARPPing::arp_buffer();

        let arp_ether = ARPPing::build_ethernet(&mut buffer, source_ip, source_mac, target_ip, target_mac).unwrap();
        let arp_ether2 = arp_ether.to_immutable();
        let parsed = ARPPing::from_ethernet(&arp_ether2).unwrap();

        assert_eq!(parsed.get_sender_proto_addr(), source_ip);
        assert_eq!(parsed.get_sender_hw_addr(), source_mac);
        assert_eq!(parsed.get_target_proto_addr(), target_ip);
        assert_eq!(parsed.get_target_hw_addr(), target_mac);
    }
}
