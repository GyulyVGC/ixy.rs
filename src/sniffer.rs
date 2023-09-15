use std::fmt::{Display, Formatter};
use etherparse::{Ethernet2Header, IpHeader, PacketHeaders, TransportHeader};
use crate::Packet;

#[derive(Debug)]
pub enum PacketDirection {
    Incoming,
    Outgoing
}

pub fn print_packet_info(pkt_data: &[u8], direction: PacketDirection) {
    // packet directionality
    debug!("{:?} packet sniffed!", direction);
    // total size (headers + payload)
    debug!("    - Total size: {} B", pkt_data.len());
    if let Ok(headers) = PacketHeaders::from_ethernet_slice(pkt_data) {
        // payload
        debug!("    - Payload size: {}", headers.payload.len());
        debug!("    - Payload content: {}", String::from_utf8_lossy(headers.payload).into_owned());

        // ip layer
        if let Some(ip) = headers.ip {
            let ip_layer = match ip {
                IpHeader::Version4(_, _) => {"IPv4"}
                IpHeader::Version6(_, _) => {"IPv6"}
            };
            debug!("    - IP version: {ip_layer}");
        } else {
            debug!("    - Cannot parse packet's IP header")
        }

        // transport layer
        if let Some(transport) = headers.transport {
            let transport_layer = match transport {
                TransportHeader::Udp(_) => {"UDP"}
                TransportHeader::Tcp(_) => {"TCP"}
                TransportHeader::Icmpv4(_) => {"ICMPv4"}
                TransportHeader::Icmpv6(_) => {"ICMPv6"}
            };
            debug!("    - Transport protocol {transport_layer}");
        } else {
            debug!("    - Cannot parse packet's transport header")
        }

    } else {
        debug!("    - Cannot parse packet's headers...");
    }
}