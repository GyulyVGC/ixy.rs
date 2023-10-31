use crate::dev::firewall::{FwAction, FwRule, PacketDirection};
use colored::Colorize;
use etherparse::{IpHeader, PacketHeaders, TransportHeader};

pub fn firewall_action_for_packet(
    packet: &[u8],
    direction: PacketDirection,
    firewall_rules: &Vec<FwRule>,
) -> FwAction {
    let mut action = FwAction::default();
    let mut current_specificity = 0;
    for rule in firewall_rules {
        if rule.matches_packet(packet, &direction) && rule.specificity() >= current_specificity {
            current_specificity = rule.specificity();
            action = rule.action;
        }
    }
    action
}

pub fn print_packet_info(pkt_data: &[u8], direction: PacketDirection, action: FwAction) {
    let mut src_port = 0;
    let mut dst_port = 0;
    let mut src_mac = String::new();
    let mut dst_mac = String::new();
    let mut ether_type = 0;
    let mut src_ip = String::new();
    let mut dst_ip = String::new();
    let color = if direction.eq(&PacketDirection::Out) {
        "blue"
    } else {
        "purple"
    };
    let policy = format!("{:?}", action);
    // total size (headers + payload)
    let size = pkt_data.len();
    if let Ok(headers) = PacketHeaders::from_ethernet_slice(pkt_data) {
        // link layer
        // let mut link_layer = "////".to_string();
        if let Some(link) = headers.link {
            src_mac = format_mac_address(link.source);
            dst_mac = format_mac_address(link.destination);
            ether_type = link.ether_type;
            // link_layer = format!("Ether type {}", link.ether_type);
        }
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
                TransportHeader::Icmpv4(_) => "ICMPv4",
                TransportHeader::Icmpv6(_) => "ICMPv6",
            }
        } else {
            "////"
        };

        // if ip_layer.ne("////")
        //     || transport_layer.ne("////")
        //     || direction.eq(&PacketDirection::Outgoing)
        // {
        println!(
            "{}",
            format!(
                "{:?} packet: {:^6}B | {:^6} | {:^6}",
                direction, size, ip_layer, transport_layer
            )
            .color(color)
        );
        println!("{}", format!("Policy: {}", policy).color(color));
        println!("{}", format!("From: {}:{}", src_ip, src_port).color(color));
        println!("{}", format!("To:   {}:{}", dst_ip, dst_port).color(color));
        println!("{}", format!("Source MAC: {}", src_mac).color(color));
        println!("{}", format!("Destination MAC: {}", dst_mac).color(color));
        println!(
            "{}",
            format!(
                "Payload: {}",
                String::from_utf8_lossy(headers.payload).into_owned()
            )
            .color(color)
        );
        if ether_type.eq(&2054) {
            // ARP
            let operation = if headers.payload[7] == 1 {
                "request"
            } else if headers.payload[7] == 2 {
                "reply"
            } else {
                ""
            };
            println!("{}", "This is an ARP packet!".color("green"));
            println!("{}", format!("Operation: {}", operation).color("green"));
            println!(
                "{}",
                format!("Sender IP: {:?}", &headers.payload[14..18]).color("green")
            );
            println!(
                "{}",
                format!("Target IP: {:?}", &headers.payload[24..28]).color("green")
            );
        }
        println!("{}", "-".repeat(42));
        // }
    } else {
        println!("Cannot extract packet's headers...");
    }
}

fn format_mac_address(mac_dec: [u8; 6]) -> String {
    let mut mac_hex = String::new();
    for n in &mac_dec {
        mac_hex.push_str(&format!("{n:02x}:"));
    }
    mac_hex.pop();
    mac_hex
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
/// use ixy::dev::sniffer::format_ipv6_address;
/// let result = format_ipv6_address([255,10,10,255,0,0,0,0,28,4,4,28,255,1,0,0]);
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
