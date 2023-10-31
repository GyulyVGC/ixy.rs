use crate::dev::fields::{get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport};
use etherparse::PacketHeaders;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::ops::{RangeInclusive};
use std::str::FromStr;
use std::u16;

#[derive(Debug, Eq, PartialEq)]
pub enum PacketDirection {
    In,
    Out,
}

impl Display for PacketDirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            PacketDirection::In => "IN",
            PacketDirection::Out => "OUT",
        };

        write!(f, "{}", str)
    }
}

impl FromStr for PacketDirection {
    type Err = FwError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "IN" => Ok(Self::In),
            "OUT" => Ok(Self::Out),
            _ => Err(FwError::InvalidDirection),
        }
    }
}

#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
pub enum FwAction {
    #[default]
    Accept,
    Deny,
    Reject,
}

impl Display for FwAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            FwAction::Accept => "ACCEPT",
            FwAction::Deny => "DENY",
            FwAction::Reject => "REJECT",
        };

        write!(f, "{}", str)
    }
}

impl FromStr for FwAction {
    type Err = FwError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ACCEPT" => Ok(Self::Accept),
            "DENY" => Ok(Self::Deny),
            "REJECT" => Ok(Self::Reject),
            _ => Err(FwError::InvalidAction),
        }
    }
}

#[derive(Debug)]
pub enum FwError {
    InvalidPorts,
    InvalidIps,
    InvalidIcmpType,
    InvalidProtocol,
    InvalidDirection,
    InvalidAction,
    UnknownOption,
    NotEnoughArguments,
    EmptyOption,
    DuplicatedOption,
    NotApplicableIcmpType,
}

impl Display for FwError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_info = match self {
            FwError::InvalidPorts => "incorrect port(s) specification",
            FwError::InvalidIps => "incorrect IP(s) specification",
            FwError::InvalidIcmpType => "incorrect ICMP type specification",
            FwError::InvalidProtocol => "incorrect protocol specification",
            FwError::InvalidDirection => "incorrect direction",
            FwError::InvalidAction => "incorrect action",
            FwError::UnknownOption => "the specified option doesn't exists",
            FwError::NotEnoughArguments => "not enough arguments supplied for rule",
            FwError::EmptyOption => "each option must have a value",
            FwError::DuplicatedOption => "duplicated option for the same rule",
            FwError::NotApplicableIcmpType => "--icmp-type is only valid for protocol numbers 1 or 58",
        };

        write!(f, "Firewall error: {}", err_info)
    }
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
                    u16::from_str(subparts.next().expect(&FwError::InvalidPorts.to_string()))
                        .expect(&FwError::InvalidPorts.to_string()),
                    u16::from_str(subparts.next().expect(&FwError::InvalidPorts.to_string()))
                        .expect(&FwError::InvalidPorts.to_string()),
                );
                ranges.push(range);
            } else {
                // individual port
                let port = u16::from_str(part).expect(&FwError::InvalidPorts.to_string());
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
                    IpAddr::from_str(subparts.next().expect(&FwError::InvalidIps.to_string()))
                        .expect(&FwError::InvalidIps.to_string()),
                    IpAddr::from_str(subparts.next().expect(&FwError::InvalidIps.to_string()))
                        .expect(&FwError::InvalidIps.to_string()),
                );
                ranges.push(range);
            } else {
                // individual IP
                let ip = IpAddr::from_str(part).expect(&FwError::InvalidIps.to_string());
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
    const DEST: &'static str = "--dest";
    const DPORT: &'static str = "--dport";
    const ICMPTYPE: &'static str = "--icmp-type";
    const PROTO: &'static str = "--proto";
    const SOURCE: &'static str = "--source";
    const SPORT: &'static str = "--sport";

    pub fn new(option: &str, value: &str) -> Self {
        match option {
            FwOption::DEST => Self::Dest(IpCollection::new(value)),
            FwOption::DPORT => Self::Dport(PortCollection::new(value)),
            FwOption::ICMPTYPE => {
                Self::IcmpType(u8::from_str(value).expect(&FwError::InvalidIcmpType.to_string()))
            }
            FwOption::PROTO => {
                Self::Proto(u8::from_str(value).expect(&FwError::InvalidProtocol.to_string()))
            }
            FwOption::SOURCE => Self::Source(IpCollection::new(value)),
            FwOption::SPORT => Self::Sport(PortCollection::new(value)),
            _ => panic!("{}", FwError::UnknownOption.to_string()),
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
            FwOption::Dest(_) => FwOption::DEST,
            FwOption::Dport(_) => FwOption::DPORT,
            FwOption::Proto(_) => FwOption::PROTO,
            FwOption::Source(_) => FwOption::SOURCE,
            FwOption::Sport(_) => FwOption::SPORT,
            FwOption::IcmpType(_) => FwOption::ICMPTYPE,
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
        let direction_str = parts.next().expect(&FwError::NotEnoughArguments.to_string());
        let direction = PacketDirection::from_str(direction_str).expect(&FwError::InvalidDirection.to_string());

        // rule action
        let action_str = parts.next().expect(&FwError::NotEnoughArguments.to_string());
        let action = FwAction::from_str(action_str).expect(&FwError::InvalidAction.to_string());

        // rule options
        let mut options = Vec::new();
        loop {
            let option = parts.next();
            if option.is_some() {
                let firewall_option = FwOption::new(
                    option.unwrap(),
                    parts.next().expect(&FwError::EmptyOption.to_string()),
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

    pub fn validate_options(options: &Vec<FwOption>) {
        let mut options_map = HashMap::new();

        // check there is no duplicate options
        for option in options {
            if options_map.insert(option.to_option_str(), option).is_some() {
                panic!("{}", FwError::DuplicatedOption.to_string());
            }
        }

        // if --icmp-type option is present, --proto 1 || --proto 58 must also be present
        // from Proxmox VE documentation: --icmp-type is only valid if --proto equals icmp or ipv6-icmp
        // icmp = 1, ipv6-icmp = 58 (<https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>)
        if options_map.contains_key(FwOption::ICMPTYPE) {
            match options_map.get(FwOption::PROTO) {
                None => {
                    panic!("{}", FwError::NotApplicableIcmpType.to_string());
                }
                Some(FwOption::Proto(x)) if *x != 1 && *x != 58 => {
                    panic!("{}", FwError::NotApplicableIcmpType.to_string());
                }
                _ => {}
            }
        }
    }
}
