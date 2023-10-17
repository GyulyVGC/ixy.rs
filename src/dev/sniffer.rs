use colored::{Colorize};
use etherparse::{IpHeader, PacketHeaders, TransportHeader};

#[derive(Debug, Eq, PartialEq)]
pub enum PacketDirection {
    Incoming,
    Outgoing
}

#[derive(Default)]
pub struct Filters {
    pub dest_port: Option<u16>,
}

pub fn is_packet_blocked(pkt_data: &[u8], filters: &Filters) -> bool {
    if filters.dest_port.is_none() {
        false
    } else {
        if let Ok(headers) = PacketHeaders::from_ethernet_slice(pkt_data) {
            if let Some(transport) = headers.transport {
                let dest_port = match transport {
                    TransportHeader::Udp(h) => h.destination_port,
                    TransportHeader::Tcp(h) => h.destination_port,
                    TransportHeader::Icmpv4(_) => 0,
                    TransportHeader::Icmpv6(_) => 0,
                };
                if dest_port.eq(&filters.dest_port.unwrap()) {
                    return true;
                }
            }
        }
        false
    }
}

pub fn print_packet_info(pkt_data: &[u8], direction: PacketDirection, is_packet_blocked: bool) {
    let mut src_port = 0;
    let mut dst_port = 0;
    let mut src_ip = String::new();
    let mut dst_ip = String::new();
    let color = if direction.eq(&PacketDirection::Outgoing) {
        "blue"
    } else {
        "purple"
    };
    let policy = if is_packet_blocked {
        "DROPPED"
    } else {
        "ACCEPTED"
    };
    // total size (headers + payload)
    let size = pkt_data.len();
    if let Ok(headers) = PacketHeaders::from_ethernet_slice(pkt_data) {
        // ip layer
        let ip_layer = if let Some(ip) = headers.ip {
            match ip {
                IpHeader::Version4(h, _) => {
                    src_ip = format_ipv4_address(h.source);
                    dst_ip = format_ipv4_address(h.destination);
                    "IPv4"
                }
                IpHeader::Version6(h, _) => {
                    src_ip = format_ipv6_address(h.source);
                    dst_ip = format_ipv6_address(h.destination);
                    "IPv6"
                }
            }
        } else {
            "////"
        };
        // transport layer
        let transport_layer = if let Some(transport) = headers.transport {
            match transport {
                TransportHeader::Udp(h) => {
                    src_port = h.source_port;
                    dst_port = h.destination_port;
                    "UDP"
                }
                TransportHeader::Tcp(h) => {
                    src_port = h.source_port;
                    dst_port = h.destination_port;
                    "TCP"
                }
                TransportHeader::Icmpv4(_) => {"ICMPv4"}
                TransportHeader::Icmpv6(_) => {"ICMPv6"}
            }
        } else {
            "////"
        };
        println!("{}", format!("{:?} packet: {:^6}B | {:^6} | {:^6}", direction, size, ip_layer, transport_layer).color(color));
        println!("{}", format!("Policy: {}", policy).color(color));
        println!("{}", format!("From: {}:{}", src_ip, src_port).color(color));
        println!("{}", format!("To:   {}:{}", dst_ip, dst_port).color(color));
        // println!("[Payload start]");
        println!("{}",format!("Payload: {}", String::from_utf8_lossy(headers.payload).into_owned()).color(color));
        // println!("[Payload end]");
        println!("{}","-".repeat(42));
    } else {
        println!("Cannot parse packet's headers...");
    }
}

pub fn format_ipv4_address(address: [u8; 4]) -> String {
    format!("{:?}", address)
        .replace('[', "")
        .replace(']', "")
        .replace(',', ".")
        .replace(' ', "")
}

/// Function to convert a long decimal ipv6 address to a
/// shorter compressed ipv6 address
///
/// # Arguments
///
/// * `ipv6_long` - Contains the 16 integer composing the not compressed decimal ipv6 address
///
/// # Example
///
/// ```
/// let result = ipv6_from_long_dec_to_short_hex([255,10,10,255,0,0,0,0,28,4,4,28,255,1,0,0]);
/// assert_eq!(result, "ff0a:aff::1c04:41c:ff01:0".to_string());
/// ```
pub fn format_ipv6_address(ipv6_long: [u8; 16]) -> String {
    //from hex to dec, paying attention to the correct number of digits
    let mut ipv6_hex = String::new();
    for i in 0..=15 {
        //even: first byte of the group
        if i % 2 == 0 {
            if *ipv6_long.get(i).unwrap() == 0 {
                continue;
            }
            ipv6_hex.push_str(&format!("{:x}", ipv6_long.get(i).unwrap()));
        }
        //odd: second byte of the group
        else if *ipv6_long.get(i - 1).unwrap() == 0 {
            ipv6_hex.push_str(&format!("{:x}:", ipv6_long.get(i).unwrap()));
        } else {
            ipv6_hex.push_str(&format!("{:02x}:", ipv6_long.get(i).unwrap()));
        }
    }
    ipv6_hex.pop();

    // search for the longest zero sequence in the ipv6 address
    let mut to_compress: Vec<&str> = ipv6_hex.split(':').collect();
    let mut longest_zero_sequence = 0; // max number of consecutive zeros
    let mut longest_zero_sequence_start = 0; // first index of the longest sequence of zeros
    let mut current_zero_sequence = 0;
    let mut current_zero_sequence_start = 0;
    let mut i = 0;
    for s in to_compress.clone() {
        if s.eq("0") {
            if current_zero_sequence == 0 {
                current_zero_sequence_start = i;
            }
            current_zero_sequence += 1;
        } else if current_zero_sequence != 0 {
            if current_zero_sequence > longest_zero_sequence {
                longest_zero_sequence = current_zero_sequence;
                longest_zero_sequence_start = current_zero_sequence_start;
            }
            current_zero_sequence = 0;
        }
        i += 1;
    }
    if current_zero_sequence != 0 {
        // to catch consecutive zeros at the end
        if current_zero_sequence > longest_zero_sequence {
            longest_zero_sequence = current_zero_sequence;
            longest_zero_sequence_start = current_zero_sequence_start;
        }
    }
    if longest_zero_sequence < 2 {
        // no compression needed
        return ipv6_hex;
    }

    //from longest sequence of consecutive zeros to '::'
    let mut ipv6_hex_compressed = String::new();
    for _ in 0..longest_zero_sequence {
        to_compress.remove(longest_zero_sequence_start);
    }
    i = 0;
    if longest_zero_sequence_start == 0 {
        ipv6_hex_compressed.push_str("::");
    }
    for s in to_compress {
        ipv6_hex_compressed.push_str(s);
        ipv6_hex_compressed.push(':');
        i += 1;
        if i == longest_zero_sequence_start {
            ipv6_hex_compressed.push(':');
        }
    }
    if ipv6_hex_compressed.ends_with("::") {
        return ipv6_hex_compressed;
    }
    ipv6_hex_compressed.pop();

    ipv6_hex_compressed
}