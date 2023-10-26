use crate::dev::fields::{get_dest, get_dport, get_proto, get_source, get_sport};
use etherparse::PacketHeaders;
use std::net::IpAddr;
use std::ops::{RangeInclusive};
use std::str::FromStr;
use std::u16;

#[derive(Debug, Eq, PartialEq)]
pub enum PacketDirection {
    In,
    Out,
}

#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
pub enum FwAction {
    #[default]
    Accept,
    Deny,
    Reject,
}

#[derive(Debug)]
pub struct PortCollection {
    pub ports: Vec<u16>,
    pub ranges: Vec<RangeInclusive<u16>>,
}

impl PortCollection {
    pub fn new(str: &str) -> Self {
        let mut ports = Vec::new();
        let mut ranges = Vec::new();

        let parts: Vec<&str> = str.split(',').collect();
        for part in parts {
            if part.contains(':') {
                // port range
                let mut subparts = part.split(':');
                let range = RangeInclusive::new(
                    u16::from_str(subparts.next().expect("Invalid format for firewall rule"))
                        .expect("Invalid format for firewall rule"),
                    u16::from_str(subparts.next().expect("Invalid format for firewall rule"))
                        .expect("Invalid format for firewall rule"),
                );
                ranges.push(range);
            } else {
                // individual IP
                let port = u16::from_str(part).expect("Invalid format for firewall rule");
                ports.push(port);
            }
        }

        Self { ports, ranges }
    }

    pub fn contains(&self, port: Option<u16>) -> bool {
        if let Some(num) = port.as_ref() {
            for range in &self.ranges {
                if range.contains(num) {
                    return true;
                }
            }
            self.ports.contains(num)
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct IpCollection {
    pub ips: Vec<IpAddr>,
    pub ranges: Vec<RangeInclusive<IpAddr>>,
}

impl IpCollection {
    pub fn new(str: &str) -> Self {
        let mut ips = Vec::new();
        let mut ranges = Vec::new();

        let parts: Vec<&str> = str.split(',').collect();
        for part in parts {
            if part.contains('-') {
                // IP range
                let mut subparts = part.split('-');
                let range = RangeInclusive::new(
                    IpAddr::from_str(subparts.next().expect("Invalid format for firewall rule"))
                        .expect("Invalid format for firewall rule"),
                    IpAddr::from_str(subparts.next().expect("Invalid format for firewall rule"))
                        .expect("Invalid format for firewall rule"),
                );
                ranges.push(range);
            } else {
                // individual IP
                let ip = IpAddr::from_str(part).expect("Invalid format for firewall rule");
                ips.push(ip);
            }
        }

        Self { ips, ranges }
    }

    pub fn contains(&self, ip: Option<IpAddr>) -> bool {
        if let Some(addr) = ip.as_ref() {
            for range in &self.ranges {
                if range.contains(addr) {
                    return true;
                }
            }
            self.ips.contains(addr)
        } else {
            false
        }
    }
}

// in the future I may implement this trait to achieve more robustness
// impl std::str::FromStr for IpCollection {
//     type Err = ();
//
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         todo!()
//     }
// }

/// Options associated to a specific firewall rule
#[derive(Debug)]
pub enum FwOption {
    /// Destination IP addresses
    Dest(IpCollection),
    /// Destination ports
    Dport(PortCollection),
    // /// ICMP message type
    // IcmpType(u8),
    /// IP protocol number
    Proto(u8),
    /// Source IP addresses
    Source(IpCollection),
    /// Source ports
    Sport(PortCollection),
}

impl FwOption {
    pub fn new(option: &str, value: &str) -> Self {
        match option {
            "--dest" => Self::Dest(IpCollection::new(value)),
            "--dport" => Self::Dport(PortCollection::new(value)),
            // "--icmp-type" => ,
            "--proto" => {
                Self::Proto(u8::from_str(value).expect("Invalid format for firewall rule"))
            }
            "--source" => Self::Source(IpCollection::new(value)),
            "--sport" => Self::Sport(PortCollection::new(value)),
            _ => panic!("Invalid format for firewall rule"),
        }
    }

    pub fn matches_packet(&self, packet: &[u8]) -> bool {
        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet) {
            let ip_header = headers.ip;
            let transport_header = headers.transport;
            match self {
                FwOption::Dest(ip_collection) => ip_collection.contains(get_dest(ip_header)),
                FwOption::Dport(port_collection) => {
                    port_collection.contains(get_dport(transport_header))
                }
                // FwOption::IcmpType(icmp_type) => {
                //     let observed_icmp = get_icmp_type(transport_header);
                //     if observed_icmp.is_none() {
                //         false
                //     } else {
                //         icmp_type.eq(&observed_icmp.unwrap())
                //     }
                // }
                FwOption::Proto(proto) => {
                    let observed_proto = get_proto(ip_header);
                    if observed_proto.is_none() {
                        false
                    } else {
                        proto.eq(&observed_proto.unwrap())
                    }
                }
                FwOption::Source(ip_collection) => ip_collection.contains(get_source(ip_header)),
                FwOption::Sport(port_collection) => {
                    port_collection.contains(get_sport(transport_header))
                }
            }
        } else {
            false
        }
    }
}

/// A firewall rule
#[derive(Debug)]
pub struct FwRule {
    pub direction: PacketDirection,
    pub action: FwAction,
    pub options: Vec<FwOption>,
}

impl FwRule {
    pub fn new(rule_str: &str) -> Self {
        let mut parts = rule_str.split(' ');

        // rule direction
        let direction_str = parts.next().expect("Invalid format for firewall rule");
        let direction = match direction_str {
            "IN" => PacketDirection::In,
            "OUT" => PacketDirection::Out,
            _ => panic!("Invalid format for firewall rule"),
        };

        // rule action
        let action_str = parts.next().expect("Invalid format for firewall rule");
        let action = match action_str {
            "ACCEPT" => FwAction::Accept,
            "DENY" => FwAction::Deny,
            "REJECT" => FwAction::Reject,
            _ => panic!("Invalid format for firewall rule"),
        };

        // rule options
        let mut options = Vec::new();
        loop {
            let option = parts.next();
            if option.is_some() {
                let firewall_option = FwOption::new(
                    option.unwrap(),
                    parts.next().expect("Invalid format for firewall rule"),
                );
                options.push(firewall_option);
            } else {
                break;
            }
        }

        Self {
            direction,
            action,
            options,
        }
    }

    pub fn matches_packet(&self, packet: &[u8], direction: &PacketDirection) -> bool {
        for option in &self.options {
            if !option.matches_packet(packet) {
                return false;
            }
        }
        self.direction.eq(direction)
    }

    pub fn specificity(&self) -> usize {
        self.options.len()
    }
}
