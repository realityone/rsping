use clap::{App, Arg, ArgMatches};
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ipv4::MutableIpv4Packet;

use super::Cmd;

lazy_static!{
    static ref MINIMUM_BUFFER_SIZE: usize = MutableIcmpPacket::minimum_packet_size() + MutableIpv4Packet::minimum_packet_size();
}

pub struct IcmpPing;

impl Cmd for IcmpPing {
    fn name() -> String {
        "icmp".to_string()
    }

    fn subcommand<'a, 'b>() -> App<'a, 'b> {
        App::new(Self::name())
            .about("Ping destination by sending ICMP packets")
            .arg(Arg::with_name("target").required(true))
    }

    fn execute<'a>(app: &ArgMatches<'a>) {
        unimplemented!()
    }
}