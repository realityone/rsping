pub mod icmp;
pub mod arp;
pub mod tcp;

use std::time::Duration;

use clap::{App, ArgMatches};
use pnet::util::MacAddr;

use error::*;

type PingResult<T> = Result<(T, usize, Duration)>;


pub trait Cmd {
    fn name() -> String;
    fn subcommand<'a, 'b>() -> App<'a, 'b>;
    fn execute<'a>(app: &ArgMatches<'a>);
}

pub const BROADCAST_MAC: MacAddr = MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);