extern crate pnet;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
extern crate clap;

pub mod error;
mod ping;
mod utils;

use clap::{App, AppSettings, Arg, SubCommand};

use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn main() {
    let arp = SubCommand::with_name("arp")
        .about("Ping destination by sending ARP packets")
        .arg(Arg::with_name("target").required(true));

    let icmp = SubCommand::with_name("icmp")
        .about("Ping destination by sending ICMP packets")
        .arg(Arg::with_name("target").required(true));

    let tcp = SubCommand::with_name("tcp")
        .about("Ping destination by sending TCP packets")
        .arg(Arg::with_name("target").required(true));

    let cli = App::new("rsping")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::GlobalVersion)
        .version("0.1")
        .author("realityone <realityone@me.com>")
        .about("The network ping utils")
        .arg(Arg::with_name("d")
                 .short("d")
                 .multiple(true)
                 .help("Print debug information verbosely"))
        .subcommand(arp.display_order(1))
        .subcommand(icmp.display_order(2))
        .subcommand(tcp.display_order(3));

    let matches = cli.get_matches();
}
