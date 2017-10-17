use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ipv4::MutableIpv4Packet;

lazy_static!{
    static ref MINIMUM_BUFFER_SIZE: usize = MutableIcmpPacket::minimum_packet_size() + MutableIpv4Packet::minimum_packet_size();
}
