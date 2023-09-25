use std::fmt::{Display, Formatter};
use etherparse::{Ethernet2Header, IpHeader, PacketHeaders, TransportHeader};
use crate::Packet;

#[derive(Debug)]
pub enum PacketDirection {
    Incoming,
    Outgoing
}

pub fn print_packet_info(pkt_data: &[u8], direction: PacketDirection) {
    // total size (headers + payload)
    let size = pkt_data.len();
    if let Ok(headers) = PacketHeaders::from_ethernet_slice(pkt_data) {
        // payload
        let payload = String::from_utf8_lossy(headers.payload).into_owned();
        // ip layer
        let ip_layer = if let Some(ip) = headers.ip {
            match ip {
                IpHeader::Version4(_, _) => {"IPv4"}
                IpHeader::Version6(_, _) => {"IPv6"}
            }
        } else {
            "////"
        };
        // transport layer
        let transport_layer = if let Some(transport) = headers.transport {
            match transport {
                TransportHeader::Udp(_) => {"UDP"}
                TransportHeader::Tcp(_) => {"TCP"}
                TransportHeader::Icmpv4(_) => {"ICMPv4"}
                TransportHeader::Icmpv6(_) => {"ICMPv6"}
            }
        } else {
            "////"
        };
        println!("{}","-".repeat(42));
        println!("{:?} packet: {:^6}B | {:^6} | {:^6}", direction, size, ip_layer, transport_layer);
        println!("Payload: {}", payload);
        println!("{}","-".repeat(42));
    } else {
        debug!("Cannot parse packet's headers...");
    }
}