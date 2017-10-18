extern crate pnet;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
extern crate clap;
extern crate ipnetwork;

mod error;
mod ping;
mod utils;

use clap::{App, AppSettings, Arg};

use ping::Cmd;
use ping::arp::ARPPing;

fn cmd_main() {
    let arp = ARPPing::subcommand();
    let icmp = ping::icmp::IcmpPing::subcommand();
    let tcp = ping::tcp::TcpPing::subcommand();

    let app = App::new("rsping")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::GlobalVersion)
        .version("0.1")
        .author("realityone <realityone@me.com>")
        .about("The network ping utils")
        .arg(Arg::with_name("d").short("d").help("Print debug information verbosely"))
        .subcommand(arp.display_order(1))
        .subcommand(icmp.display_order(2))
        .subcommand(tcp.display_order(3));

    let matches = app.get_matches();

    // subcommand is required
    let (subc_name, subc_matchs) = matches.subcommand();
    if subc_name == ARPPing::name() {
        ARPPing::execute(subc_matchs.unwrap());
    };
}

fn main() {
    cmd_main();
}
