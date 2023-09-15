use etherparse::{PacketHeaders, TransportHeader};
use crate::Packet;

pub fn print_packet_info(pkt_data: &[u8]) {
    if let Ok(headers) = PacketHeaders::from_ethernet_slice(pkt_data) {
        if let Some(transport) = headers.transport {
            let transport_layer = match transport {
                TransportHeader::Udp(_) => {"UDP"}
                TransportHeader::Tcp(_) => {"TCP"}
                TransportHeader::Icmpv4(_) => {"ICMPv4"}
                TransportHeader::Icmpv6(_) => {"ICMPv6"}
            };
            debug!("Sniffed a {transport_layer} packet!");
        } else {
            debug!("Cannot parse packet's transport header")
        }
    } else {
        debug!("Cannot parse packet's headers...");
    }
}