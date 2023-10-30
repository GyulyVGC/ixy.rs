use crate::dev::fields::{get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport};
use etherparse::PacketHeaders;
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::RangeInclusive;
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

/// Options associated to a specific firewall rule
#[derive(Debug)]
pub enum FwOption {
    /// Destination IP addresses
    Dest(IpCollection),
    /// Destination ports
    Dport(PortCollection),
    /// ICMP message type
    IcmpType(u8),
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
            "--icmp-type" => {
                Self::IcmpType(u8::from_str(value).expect("Invalid format for firewall rule"))
            }
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
                FwOption::IcmpType(icmp_type) => {
                    if let Some(observed_icmp) = get_icmp_type(transport_header) {
                        icmp_type.eq(&observed_icmp)
                    } else {
                        false
                    }
                }
                FwOption::Proto(proto) => {
                    if let Some(observed_proto) = get_proto(ip_header) {
                        proto.eq(&observed_proto)
                    } else {
                        false
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

    pub fn to_option_str(&self) -> &str {
        match self {
            FwOption::Dest(_) => "--dest",
            FwOption::Dport(_) => "--dport",
            FwOption::Proto(_) => "--proto",
            FwOption::Source(_) => "--sorce",
            FwOption::Sport(_) => "--sport",
            FwOption::IcmpType(_) => "--icmp-type",
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

        FwRule::validate_options(&options);

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

    pub fn validate_options(mut options: &Vec<FwOption>) {
        let mut options_map = HashMap::new();

        // check there is no duplicate options
        for option in options {
            if options_map.insert(option.to_option_str(), option).is_some() {
                panic!("Invalid format for firewall rule");
            }
        }

        // remove --icmp-type option if protocol number is not compatible or absent
        // from Proxmox VE documentation: --icmp-type is only valid if --proto equals icmp or ipv6-icmp
        // icmp = 1, ipv6-icmp = 58 (<https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>)
        if options_map.contains_key("--icmp-type") {
            let mut remove_icmp_option = false;
            match options_map.get("--proto") {
                None => {
                    remove_icmp_option = true;
                }
                Some(FwOption::Proto(x)) if *x != 1 && *x != 58 => {
                    remove_icmp_option = true;
                }
                _ => {}
            }
            if remove_icmp_option {
                options = options
                    .drain(..)
                    .filter(|opt| match opt {
                        FwOption::IcmpType(_) => false,
                        _ => true,
                    })
                    .collect();
            }
        }
    }
}
