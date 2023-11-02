use crate::dev::fields::{get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport};
use etherparse::PacketHeaders;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::u16;

#[derive(Debug, Eq, PartialEq)]
pub enum FirewallDirection {
    In,
    Out,
}

impl Display for FirewallDirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            FirewallDirection::In => "IN",
            FirewallDirection::Out => "OUT",
        };

        write!(f, "{}", str)
    }
}

impl FromStr for FirewallDirection {
    type Err = FirewallError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "IN" => Ok(Self::In),
            "OUT" => Ok(Self::Out),
            _ => Err(FirewallError::InvalidDirection),
        }
    }
}

#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
pub enum FirewallAction {
    #[default]
    Accept,
    Deny,
    Reject,
}

impl Display for FirewallAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            FirewallAction::Accept => "ACCEPT",
            FirewallAction::Deny => "DENY",
            FirewallAction::Reject => "REJECT",
        };

        write!(f, "{}", str)
    }
}

impl FromStr for FirewallAction {
    type Err = FirewallError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ACCEPT" => Ok(Self::Accept),
            "DENY" => Ok(Self::Deny),
            "REJECT" => Ok(Self::Reject),
            _ => Err(FirewallError::InvalidAction),
        }
    }
}

#[derive(Debug)]
pub enum FirewallError {
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

impl Display for FirewallError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_info = match self {
            FirewallError::InvalidPorts => "incorrect port(s) specification",
            FirewallError::InvalidIps => "incorrect IP(s) specification",
            FirewallError::InvalidIcmpType => "incorrect ICMP type specification",
            FirewallError::InvalidProtocol => "incorrect protocol specification",
            FirewallError::InvalidDirection => "incorrect direction",
            FirewallError::InvalidAction => "incorrect action",
            FirewallError::UnknownOption => "the specified option doesn't exists",
            FirewallError::NotEnoughArguments => "not enough arguments supplied for rule",
            FirewallError::EmptyOption => "each option must have a value",
            FirewallError::DuplicatedOption => "duplicated option for the same rule",
            FirewallError::NotApplicableIcmpType => {
                "--icmp-type is only valid for protocol numbers 1 or 58"
            }
        };

        write!(f, "Firewall error - {}", err_info)
    }
}

#[derive(Debug, Eq, PartialEq)]
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
                let range =
                    RangeInclusive::new(
                        u16::from_str(subparts.next().unwrap_or_else(|| {
                            panic!("{}", FirewallError::InvalidPorts.to_string())
                        }))
                        .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidPorts.to_string())),
                        u16::from_str(subparts.next().unwrap_or_else(|| {
                            panic!("{}", FirewallError::InvalidPorts.to_string())
                        }))
                        .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidPorts.to_string())),
                    );
                ranges.push(range);
            } else {
                // individual port
                let port = u16::from_str(part)
                    .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidPorts.to_string()));
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

#[derive(Debug, Eq, PartialEq)]
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
                let range =
                    RangeInclusive::new(
                        IpAddr::from_str(subparts.next().unwrap_or_else(|| {
                            panic!("{}", FirewallError::InvalidIps.to_string())
                        }))
                        .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidIps.to_string())),
                        IpAddr::from_str(subparts.next().unwrap_or_else(|| {
                            panic!("{}", FirewallError::InvalidIps.to_string())
                        }))
                        .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidIps.to_string())),
                    );
                ranges.push(range);
            } else {
                // individual IP
                let ip = IpAddr::from_str(part)
                    .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidIps.to_string()));
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
#[derive(Debug, Eq, PartialEq)]
pub enum FirewallOption {
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

impl FirewallOption {
    const DEST: &'static str = "--dest";
    const DPORT: &'static str = "--dport";
    const ICMPTYPE: &'static str = "--icmp-type";
    const PROTO: &'static str = "--proto";
    const SOURCE: &'static str = "--source";
    const SPORT: &'static str = "--sport";

    pub fn new(option: &str, value: &str) -> Self {
        match option {
            FirewallOption::DEST => Self::Dest(IpCollection::new(value)),
            FirewallOption::DPORT => Self::Dport(PortCollection::new(value)),
            FirewallOption::ICMPTYPE => Self::IcmpType(
                u8::from_str(value)
                    .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidIcmpType.to_string())),
            ),
            FirewallOption::PROTO => Self::Proto(
                u8::from_str(value)
                    .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidProtocol.to_string())),
            ),
            FirewallOption::SOURCE => Self::Source(IpCollection::new(value)),
            FirewallOption::SPORT => Self::Sport(PortCollection::new(value)),
            _ => panic!("{}", FirewallError::UnknownOption.to_string()),
        }
    }

    pub fn matches_packet(&self, packet: &[u8]) -> bool {
        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet) {
            let ip_header = headers.ip;
            let transport_header = headers.transport;
            match self {
                FirewallOption::Dest(ip_collection) => ip_collection.contains(get_dest(ip_header)),
                FirewallOption::Dport(port_collection) => {
                    port_collection.contains(get_dport(transport_header))
                }
                FirewallOption::IcmpType(icmp_type) => {
                    if let Some(observed_icmp) = get_icmp_type(transport_header) {
                        icmp_type.eq(&observed_icmp)
                    } else {
                        false
                    }
                }
                FirewallOption::Proto(proto) => {
                    if let Some(observed_proto) = get_proto(ip_header) {
                        proto.eq(&observed_proto)
                    } else {
                        false
                    }
                }
                FirewallOption::Source(ip_collection) => {
                    ip_collection.contains(get_source(ip_header))
                }
                FirewallOption::Sport(port_collection) => {
                    port_collection.contains(get_sport(transport_header))
                }
            }
        } else {
            false
        }
    }

    pub fn to_option_str(&self) -> &str {
        match self {
            FirewallOption::Dest(_) => FirewallOption::DEST,
            FirewallOption::Dport(_) => FirewallOption::DPORT,
            FirewallOption::Proto(_) => FirewallOption::PROTO,
            FirewallOption::Source(_) => FirewallOption::SOURCE,
            FirewallOption::Sport(_) => FirewallOption::SPORT,
            FirewallOption::IcmpType(_) => FirewallOption::ICMPTYPE,
        }
    }
}

/// A firewall rule
#[derive(Debug, Eq, PartialEq)]
pub struct FirewallRule {
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    pub options: Vec<FirewallOption>,
}

impl FirewallRule {
    pub fn new(rule_str: &str) -> Self {
        let mut parts = rule_str.split(' ');

        // rule direction
        let direction_str = parts
            .next()
            .unwrap_or_else(|| panic!("{}", FirewallError::NotEnoughArguments.to_string()));
        let direction = FirewallDirection::from_str(direction_str)
            .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidDirection.to_string()));

        // rule action
        let action_str = parts
            .next()
            .unwrap_or_else(|| panic!("{}", FirewallError::NotEnoughArguments.to_string()));
        let action = FirewallAction::from_str(action_str)
            .unwrap_or_else(|_| panic!("{}", FirewallError::InvalidAction.to_string()));

        // rule options
        let mut options = Vec::new();
        loop {
            let option = parts.next();
            if let Some(option_str) = option {
                let firewall_option = FirewallOption::new(
                    option_str,
                    parts
                        .next()
                        .unwrap_or_else(|| panic!("{}", FirewallError::EmptyOption.to_string())),
                );
                options.push(firewall_option);
            } else {
                break;
            }
        }

        FirewallRule::validate_options(&options);

        Self {
            direction,
            action,
            options,
        }
    }

    pub fn matches_packet(&self, packet: &[u8], direction: &FirewallDirection) -> bool {
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

    pub fn validate_options(options: &Vec<FirewallOption>) {
        let mut options_map = HashMap::new();

        // check there is no duplicate options
        for option in options {
            if options_map.insert(option.to_option_str(), option).is_some() {
                panic!("{}", FirewallError::DuplicatedOption.to_string());
            }
        }

        // if --icmp-type option is present, --proto 1 || --proto 58 must also be present
        // from Proxmox VE documentation: --icmp-type is only valid if --proto equals icmp or ipv6-icmp
        // icmp = 1, ipv6-icmp = 58 (<https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>)
        if options_map.contains_key(FirewallOption::ICMPTYPE) {
            match options_map.get(FirewallOption::PROTO) {
                None => {
                    panic!("{}", FirewallError::NotApplicableIcmpType.to_string());
                }
                Some(FirewallOption::Proto(x)) if *x != 1 && *x != 58 => {
                    panic!("{}", FirewallError::NotApplicableIcmpType.to_string());
                }
                _ => {}
            }
        }
    }
}

/// The firewall of our driver
#[derive(Debug, Eq, PartialEq)]
pub struct Firewall {
    pub rules: Vec<FirewallRule>,
    pub enabled: bool,
    pub policy_in: FirewallAction,
    pub policy_out: FirewallAction,
}

impl Default for Firewall {
    fn default() -> Self {
        Self {
            rules: vec![],
            enabled: false,
            policy_in: FirewallAction::default(),
            policy_out: FirewallAction::default(),
        }
    }
}

impl Firewall {
    pub fn new(file_path: &str) -> Self {
        let mut rules = Vec::new();
        let file = File::open(file_path).unwrap();
        for firewall_rule_str in BufReader::new(file).lines().flatten() {
            rules.push(FirewallRule::new(&firewall_rule_str));
        }
        Self {
            rules,
            enabled: true,
            policy_in: FirewallAction::default(),
            policy_out: FirewallAction::default(),
        }
    }

    pub fn determine_action_for_packet(
        &self,
        packet: &[u8],
        direction: FirewallDirection,
    ) -> FirewallAction {
        if !self.enabled {
            FirewallAction::Accept
        }

        let mut action = match direction {
            FirewallDirection::In => self.policy_in,
            FirewallDirection::Out => self.policy_out,
        };

        let mut current_specificity = 0;
        for rule in &self.rules {
            if rule.matches_packet(packet, &direction) && rule.specificity() >= current_specificity
            {
                current_specificity = rule.specificity();
                action = rule.action;
            }
        }
        action
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn set_policy_in(&mut self, policy: FirewallAction) {
        self.policy_in = policy;
    }

    pub fn set_policy_out(&mut self, policy: FirewallAction) {
        self.policy_out = policy;
    }
}

#[cfg(test)]
mod tests {
    use crate::dev::firewall::{
        FirewallAction, FirewallDirection, FirewallOption, FirewallRule, IpCollection,
        PortCollection,
    };
    use crate::dev::raw_packets::{ARP_PACKET, ICMP_PACKET, TCP_PACKET};
    use crate::Firewall;
    use std::net::IpAddr;
    use std::ops::RangeInclusive;
    use std::str::FromStr;

    #[test]
    fn test_new_port_collections() {
        assert_eq!(
            PortCollection::new("1,2,3,4,999"),
            PortCollection {
                ports: vec![1, 2, 3, 4, 999],
                ranges: vec![]
            }
        );

        assert_eq!(
            PortCollection::new("1,2,3,4,900:999"),
            PortCollection {
                ports: vec![1, 2, 3, 4],
                ranges: vec![900..=999]
            }
        );

        assert_eq!(
            PortCollection::new("1:999"),
            PortCollection {
                ports: vec![],
                ranges: vec![1..=999]
            }
        );

        assert_eq!(
            PortCollection::new("1,2,10:20,3,4,999:1200"),
            PortCollection {
                ports: vec![1, 2, 3, 4],
                ranges: vec![10..=20, 999..=1200]
            }
        );

        assert!(std::panic::catch_unwind(|| PortCollection::new("1,2,10:20,3,4,:1200")).is_err());

        assert!(
            std::panic::catch_unwind(|| PortCollection::new("1,2,10:20,3,4,999-1200")).is_err()
        );

        assert!(
            std::panic::catch_unwind(|| PortCollection::new("1,2,10:20,3,4,999-1200,")).is_err()
        );
    }

    #[test]
    fn test_new_ip_collections() {
        assert_eq!(
            IpCollection::new("1.1.1.1,2.2.2.2"),
            IpCollection {
                ips: vec![
                    IpAddr::from_str("1.1.1.1").unwrap(),
                    IpAddr::from_str("2.2.2.2").unwrap()
                ],
                ranges: vec![]
            }
        );

        assert_eq!(
            IpCollection::new("1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"),
            IpCollection {
                ips: vec![
                    IpAddr::from_str("1.1.1.1").unwrap(),
                    IpAddr::from_str("2.2.2.2").unwrap(),
                    IpAddr::from_str("9.9.9.9").unwrap()
                ],
                ranges: vec![
                    RangeInclusive::new(
                        IpAddr::from_str("3.3.3.3").unwrap(),
                        IpAddr::from_str("5.5.5.5").unwrap()
                    ),
                    RangeInclusive::new(
                        IpAddr::from_str("10.0.0.1").unwrap(),
                        IpAddr::from_str("10.0.0.255").unwrap()
                    )
                ]
            }
        );

        assert_eq!(
            IpCollection::new("aaaa::ffff,bbbb::1-cccc::2"),
            IpCollection {
                ips: vec![IpAddr::from_str("aaaa::ffff").unwrap(),],
                ranges: vec![RangeInclusive::new(
                    IpAddr::from_str("bbbb::1").unwrap(),
                    IpAddr::from_str("cccc::2").unwrap()
                )]
            }
        );

        assert!(std::panic::catch_unwind(|| IpCollection::new(
            "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| IpCollection::new(
            "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1:10.0.0.255,9.9.9.9"
        ))
        .is_err());
    }

    #[test]
    fn test_port_collection_contains() {
        let collection = PortCollection::new("1,2,25:30");
        assert!(collection.contains(Some(1)));
        assert!(collection.contains(Some(2)));
        assert!(collection.contains(Some(25)));
        assert!(collection.contains(Some(27)));
        assert!(collection.contains(Some(30)));
        assert!(!collection.contains(None));
        assert!(!collection.contains(Some(24)));
        assert!(!collection.contains(Some(31)));
        assert!(!collection.contains(Some(8080)));
    }

    #[test]
    fn test_ip_collection_contains() {
        let collection =
            IpCollection::new("1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9");
        assert!(collection.contains(Some(IpAddr::from_str("2.2.2.2").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("4.0.0.0").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("9.9.9.9").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("10.0.0.1").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("10.0.0.128").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("10.0.0.255").unwrap())));
        assert!(!collection.contains(None));
        assert!(!collection.contains(Some(IpAddr::from_str("10.0.0.0").unwrap())));
        assert!(!collection.contains(Some(IpAddr::from_str("2.2.2.1").unwrap())));
    }

    #[test]
    fn test_new_firewall_options() {
        assert_eq!(
            FirewallOption::new(
                "--dest",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            ),
            FirewallOption::Dest(IpCollection::new(
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            ))
        );

        assert_eq!(
            FirewallOption::new("--dport", "1,2,10:20,3,4,999:1200"),
            FirewallOption::Dport(PortCollection::new("1,2,10:20,3,4,999:1200"))
        );

        assert_eq!(
            FirewallOption::new("--icmp-type", "8"),
            FirewallOption::IcmpType(8)
        );

        assert_eq!(
            FirewallOption::new("--proto", "1"),
            FirewallOption::Proto(1)
        );

        assert_eq!(
            FirewallOption::new(
                "--source",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            ),
            FirewallOption::Source(IpCollection::new(
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            ))
        );

        assert_eq!(
            FirewallOption::new("--sport", "1,2,10:20,3,4,999:1200"),
            FirewallOption::Sport(PortCollection::new("1,2,10:20,3,4,999:1200"))
        );

        assert!(
            std::panic::catch_unwind(|| FirewallOption::new("--not-exists", "8.8.8.8")).is_err()
        );
    }

    #[test]
    fn test_new_firewall_rules() {
        assert_eq!(
            FirewallRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            FirewallRule {
                direction: FirewallDirection::Out,
                action: FirewallAction::Accept,
                options: vec![
                    FirewallOption::Source(IpCollection::new("8.8.8.8,7.7.7.7")),
                    FirewallOption::Dport(PortCollection::new("900:1000,1,2,3"))
                ]
            }
        );

        assert_eq!(
            FirewallRule::new("OUT REJECT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8 --proto 1"),
            FirewallRule {
                direction: FirewallDirection::Out,
                action: FirewallAction::Reject,
                options: vec![
                    FirewallOption::Source(IpCollection::new("8.8.8.8,7.7.7.7")),
                    FirewallOption::Dport(PortCollection::new("900:1000,1,2,3")),
                    FirewallOption::IcmpType(8),
                    FirewallOption::Proto(1)
                ]
            }
        );

        assert_eq!(
            FirewallRule::new(
                "IN DENY --dest 8.8.8.8,7.7.7.7 --sport 900:1000,1,2,3 --icmp-type 1 --proto 58"
            ),
            FirewallRule {
                direction: FirewallDirection::In,
                action: FirewallAction::Deny,
                options: vec![
                    FirewallOption::Dest(IpCollection::new("8.8.8.8,7.7.7.7")),
                    FirewallOption::Sport(PortCollection::new("900:1000,1,2,3")),
                    FirewallOption::IcmpType(1),
                    FirewallOption::Proto(58)
                ]
            }
        );

        assert!(std::panic::catch_unwind(|| FirewallRule::new(
            "ACCEPT OUT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FirewallRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FirewallRule::new(
            "OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FirewallRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3.3.3.3"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FirewallRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FirewallRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8 --proto 57"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FirewallRule::new(
            "UP ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FirewallRule::new(
            "OUT PUTAWAY --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
        ))
        .is_err());
    }

    #[test]
    fn test_options_match_packets() {
        let dest_opt = FirewallOption::new("--dest", "192.168.200.21,8.8.8.8,2.1.1.2");
        let range_dest_opt = FirewallOption::new("--dest", "192.168.200.0-192.168.200.255,8.8.8.8");
        let range_dest_opt_miss =
            FirewallOption::new("--dest", "192.168.200.0-192.168.200.20,8.8.8.8");
        let source_opt = FirewallOption::new("--source", "192.168.200.0-192.168.200.255,2.1.1.2");
        let dport_opt = FirewallOption::new("--dport", "2000");
        let range_dport_opt = FirewallOption::new("--dport", "6700:6750");
        let sport_opt_wrong = FirewallOption::new("--sport", "2000");
        let sport_opt_miss = FirewallOption::new("--sport", "6712");
        let range_sport_opt = FirewallOption::new("--sport", "6711:6750");
        let range_sport_opt_miss = FirewallOption::new("--sport", "6712:6750");
        let icmp_type_opt = FirewallOption::new("--icmp-type", "8");
        let wrong_icmp_type_opt = FirewallOption::new("--icmp-type", "7");
        let tcp_proto_opt = FirewallOption::new("--proto", "6");
        let icmp_proto_opt = FirewallOption::new("--proto", "1");

        // tcp packet
        assert!(dest_opt.matches_packet(&TCP_PACKET));
        assert!(range_dest_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&TCP_PACKET));
        assert!(source_opt.matches_packet(&TCP_PACKET));
        assert!(dport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dport_opt.matches_packet(&TCP_PACKET));
        assert!(!sport_opt_wrong.matches_packet(&TCP_PACKET));
        assert!(!sport_opt_miss.matches_packet(&TCP_PACKET));
        assert!(range_sport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_sport_opt_miss.matches_packet(&TCP_PACKET));
        assert!(!icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(tcp_proto_opt.matches_packet(&TCP_PACKET));
        assert!(!icmp_proto_opt.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(!dest_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_dest_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&ICMP_PACKET));
        assert!(source_opt.matches_packet(&ICMP_PACKET));
        assert!(!dport_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_dport_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_sport_opt.matches_packet(&ICMP_PACKET));
        assert!(icmp_type_opt.matches_packet(&ICMP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&ICMP_PACKET));
        assert!(!tcp_proto_opt.matches_packet(&ICMP_PACKET));
        assert!(icmp_proto_opt.matches_packet(&ICMP_PACKET));

        // arp packet
        assert!(!dest_opt.matches_packet(&ARP_PACKET));
        assert!(!range_dest_opt.matches_packet(&ARP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&ARP_PACKET));
        assert!(!source_opt.matches_packet(&ARP_PACKET));
        assert!(!dport_opt.matches_packet(&ARP_PACKET));
        assert!(!range_dport_opt.matches_packet(&ARP_PACKET));
        assert!(!range_sport_opt.matches_packet(&ARP_PACKET));
        assert!(!icmp_type_opt.matches_packet(&ARP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&ARP_PACKET));
        assert!(!tcp_proto_opt.matches_packet(&ARP_PACKET));
        assert!(!icmp_proto_opt.matches_packet(&ARP_PACKET));
    }

    #[test]
    fn test_rules_match_packets() {
        let rule_1 = FirewallRule::new("OUT DENY");
        assert!(rule_1.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_1.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(rule_1.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_1.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_2 = FirewallRule::new("IN DENY");
        assert!(!rule_2.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(rule_2.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_2.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(rule_2.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_3_ok_out =
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001");
        assert!(rule_3_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_3_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_3_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_3_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_4_ok_in =
            FirewallRule::new("IN REJECT --source 192.168.200.135 --dport 1999:2001");
        assert!(!rule_4_ok_in.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(rule_4_ok_in.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_4_ok_in.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_4_ok_in.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_5_ok_out =
            FirewallRule::new("OUT ACCEPT --source 192.168.200.135 --dport 1999:2001 --sport 6711");
        assert!(rule_5_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_5_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_5_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_5_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_6_ko =
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6710");
        assert!(!rule_6_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_6_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_6_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_6_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_7_ok_out = FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6711 --dest 192.168.200.10-192.168.200.21");
        assert!(rule_7_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_7_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_7_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_7_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_8_ko = FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6711 --dest 192.168.200.10-192.168.200.20");
        assert!(!rule_8_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_8_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_8_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_8_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_9_ok_in = FirewallRule::new("IN ACCEPT --proto 6");
        assert!(!rule_9_ok_in.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(rule_9_ok_in.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_9_ok_in.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_9_ok_in.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_10_ko = FirewallRule::new("IN ACCEPT --proto 58");
        assert!(!rule_10_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_10_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_10_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_10_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_11_ko = FirewallRule::new("IN ACCEPT --proto 1 --icmp-type 8");
        assert!(!rule_11_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_11_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_11_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(rule_11_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_12_ko = FirewallRule::new("OUT DENY --proto 1 --icmp-type 7");
        assert!(!rule_12_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_12_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_12_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_12_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_13_ko = FirewallRule::new("OUT DENY --proto 1 --icmp-type 8");
        assert!(!rule_13_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_13_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(rule_13_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_13_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
    }

    /// File is placed in examples/firewall_for_tests_1.txt and its content is the following:
    /// OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080
    /// OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080 --dport 1,2,2000
    /// OUT DENY --source 192.168.200.135-192.168.200.140 --sport 6700:6800,8080 --dport 1,2,2000
    /// OUT REJECT --source 192.168.200.135 --sport 6750:6800,8080 --dest 192.168.200.21 --dport 1,2,2000
    /// IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1
    /// IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8
    /// IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 9
    /// IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 58 --icmp-type 8
    /// OUT REJECT
    /// IN ACCEPT
    #[test]
    fn test_new_firewall_from_file() {
        let rules = vec![
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080"),
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080 --dport 1,2,2000"),
            FirewallRule::new("OUT DENY --source 192.168.200.135-192.168.200.140 --sport 6700:6800,8080 --dport 1,2,2000"),
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6750:6800,8080 --dest 192.168.200.21 --dport 1,2,2000"),
            FirewallRule::new("IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1"),
            FirewallRule::new("IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8"),
            FirewallRule::new("IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 9"),
            FirewallRule::new("IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 58 --icmp-type 8"),
            FirewallRule::new("OUT REJECT"),
            FirewallRule::new("IN ACCEPT"),
        ];
        let mut firewall = Firewall {
            rules,
            enabled: true,
            policy_in: FirewallAction::default(),
            policy_out: FirewallAction::default(),
        };

        assert_eq!(
            Firewall::new("./examples/firewall_for_tests_1.txt"),
            firewall
        );

        firewall.disable();
        firewall.set_policy_in(FirewallAction::Deny);
        firewall.set_policy_out(FirewallAction::Reject);
        assert!(!firewall.enabled);
        assert_eq!(firewall.policy_in, FirewallAction::Deny);
        assert_eq!(firewall.policy_out, FirewallAction::Reject);
    }

    #[test]
    fn test_determine_action_for_packet_1() {
        let firewall = Firewall::new("./examples/firewall_for_tests_1.txt");

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, FirewallDirection::Out),
            FirewallAction::Deny
        );

        // icmp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, FirewallDirection::In),
            FirewallAction::Reject
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, FirewallDirection::Out),
            FirewallAction::Reject
        );

        // arp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, FirewallDirection::Out),
            FirewallAction::Reject
        );
    }

    #[test]
    fn test_determine_action_for_packet_2() {
        let mut firewall = Firewall::new("./examples/firewall_for_tests_2.txt");
        firewall.set_policy_in(FirewallAction::Deny);
        firewall.set_policy_out(FirewallAction::Accept);

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, FirewallDirection::In),
            FirewallAction::Deny
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, FirewallDirection::Out),
            FirewallAction::Deny
        );

        // icmp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, FirewallDirection::In),
            FirewallAction::Reject
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, FirewallDirection::Out),
            FirewallAction::Accept
        );

        // arp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, FirewallDirection::In),
            FirewallAction::Deny
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, FirewallDirection::Out),
            FirewallAction::Accept
        );
    }

    #[test]
    fn test_determine_action_for_packet_with_firewall_disabled() {
        let mut firewall = Firewall::new("./examples/firewall_for_tests_1.txt");
        firewall.set_policy_in(FirewallAction::Reject); // doesn't matter
        firewall.set_policy_out(FirewallAction::Reject); // doesn't matter
        firewall.disable(); // always accept

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, FirewallDirection::Out),
            FirewallAction::Accept
        );

        // icmp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, FirewallDirection::Out),
            FirewallAction::Accept
        );

        // arp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, FirewallDirection::Out),
            FirewallAction::Accept
        );
    }
}
