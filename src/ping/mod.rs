pub mod icmp;
pub mod arp;
pub mod tcp;

use std::time::Duration;

use error::*;

type PingResult<T> = Result<(T, Duration)>;