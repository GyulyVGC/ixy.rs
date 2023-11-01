use crate::dev::fields::{get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport};
use etherparse::PacketHeaders;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::ops::RangeInclusive;
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
            FwError::NotApplicableIcmpType => {
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
                let range = RangeInclusive::new(
                    u16::from_str(
                        subparts
                            .next()
                            .unwrap_or_else(|| panic!("{}", FwError::InvalidPorts.to_string())),
                    )
                    .unwrap_or_else(|_| panic!("{}", FwError::InvalidPorts.to_string())),
                    u16::from_str(
                        subparts
                            .next()
                            .unwrap_or_else(|| panic!("{}", FwError::InvalidPorts.to_string())),
                    )
                    .unwrap_or_else(|_| panic!("{}", FwError::InvalidPorts.to_string())),
                );
                ranges.push(range);
            } else {
                // individual port
                let port = u16::from_str(part)
                    .unwrap_or_else(|_| panic!("{}", FwError::InvalidPorts.to_string()));
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
                let range = RangeInclusive::new(
                    IpAddr::from_str(
                        subparts
                            .next()
                            .unwrap_or_else(|| panic!("{}", FwError::InvalidIps.to_string())),
                    )
                    .unwrap_or_else(|_| panic!("{}", FwError::InvalidIps.to_string())),
                    IpAddr::from_str(
                        subparts
                            .next()
                            .unwrap_or_else(|| panic!("{}", FwError::InvalidIps.to_string())),
                    )
                    .unwrap_or_else(|_| panic!("{}", FwError::InvalidIps.to_string())),
                );
                ranges.push(range);
            } else {
                // individual IP
                let ip = IpAddr::from_str(part)
                    .unwrap_or_else(|_| panic!("{}", FwError::InvalidIps.to_string()));
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
            FwOption::ICMPTYPE => Self::IcmpType(
                u8::from_str(value)
                    .unwrap_or_else(|_| panic!("{}", FwError::InvalidIcmpType.to_string())),
            ),
            FwOption::PROTO => Self::Proto(
                u8::from_str(value)
                    .unwrap_or_else(|_| panic!("{}", FwError::InvalidProtocol.to_string())),
            ),
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
#[derive(Debug, Eq, PartialEq)]
pub struct FwRule {
    pub direction: PacketDirection,
    pub action: FwAction,
    pub options: Vec<FwOption>,
}

impl FwRule {
    pub fn new(rule_str: &str) -> Self {
        let mut parts = rule_str.split(' ');

        // rule direction
        let direction_str = parts
            .next()
            .unwrap_or_else(|| panic!("{}", FwError::NotEnoughArguments.to_string()));
        let direction = PacketDirection::from_str(direction_str)
            .unwrap_or_else(|_| panic!("{}", FwError::InvalidDirection.to_string()));

        // rule action
        let action_str = parts
            .next()
            .unwrap_or_else(|| panic!("{}", FwError::NotEnoughArguments.to_string()));
        let action = FwAction::from_str(action_str)
            .unwrap_or_else(|_| panic!("{}", FwError::InvalidAction.to_string()));

        // rule options
        let mut options = Vec::new();
        loop {
            let option = parts.next();
            if option.is_some() {
                let firewall_option = FwOption::new(
                    option.unwrap(),
                    parts
                        .next()
                        .unwrap_or_else(|| panic!("{}", FwError::EmptyOption.to_string())),
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

#[cfg(test)]
mod tests {
    use crate::dev::firewall::{FwAction, FwOption, IpCollection, PacketDirection, PortCollection};
    use crate::FwRule;
    use std::net::IpAddr;
    use std::ops::RangeInclusive;
    use std::str::FromStr;
    use crate::dev::raw_packets::TCP_PACKET;

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
            FwOption::new(
                "--dest",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            ),
            FwOption::Dest(IpCollection::new(
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            ))
        );

        assert_eq!(
            FwOption::new("--dport", "1,2,10:20,3,4,999:1200"),
            FwOption::Dport(PortCollection::new("1,2,10:20,3,4,999:1200"))
        );

        assert_eq!(FwOption::new("--icmp-type", "8"), FwOption::IcmpType(8));

        assert_eq!(FwOption::new("--proto", "1"), FwOption::Proto(1));

        assert_eq!(
            FwOption::new(
                "--source",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            ),
            FwOption::Source(IpCollection::new(
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            ))
        );

        assert_eq!(
            FwOption::new("--sport", "1,2,10:20,3,4,999:1200"),
            FwOption::Sport(PortCollection::new("1,2,10:20,3,4,999:1200"))
        );

        assert!(std::panic::catch_unwind(|| FwOption::new("--not-exists", "8.8.8.8")).is_err());
    }

    #[test]
    fn test_new_firewall_rules() {
        assert_eq!(
            FwRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            FwRule {
                direction: PacketDirection::Out,
                action: FwAction::Accept,
                options: vec![
                    FwOption::Source(IpCollection::new("8.8.8.8,7.7.7.7")),
                    FwOption::Dport(PortCollection::new("900:1000,1,2,3"))
                ]
            }
        );

        assert_eq!(
            FwRule::new("OUT REJECT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8 --proto 1"),
            FwRule {
                direction: PacketDirection::Out,
                action: FwAction::Reject,
                options: vec![
                    FwOption::Source(IpCollection::new("8.8.8.8,7.7.7.7")),
                    FwOption::Dport(PortCollection::new("900:1000,1,2,3")),
                    FwOption::IcmpType(8),
                    FwOption::Proto(1)
                ]
            }
        );

        assert_eq!(
            FwRule::new(
                "IN DENY --dest 8.8.8.8,7.7.7.7 --sport 900:1000,1,2,3 --icmp-type 1 --proto 58"
            ),
            FwRule {
                direction: PacketDirection::In,
                action: FwAction::Deny,
                options: vec![
                    FwOption::Dest(IpCollection::new("8.8.8.8,7.7.7.7")),
                    FwOption::Sport(PortCollection::new("900:1000,1,2,3")),
                    FwOption::IcmpType(1),
                    FwOption::Proto(58)
                ]
            }
        );

        assert!(std::panic::catch_unwind(|| FwRule::new(
            "ACCEPT OUT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FwRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FwRule::new(
            "OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FwRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3.3.3.3"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FwRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FwRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8 --proto 57"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FwRule::new(
            "UP ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
        ))
        .is_err());

        assert!(std::panic::catch_unwind(|| FwRule::new(
            "OUT PUTAWAY --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
        ))
        .is_err());
    }

    fn test_options_match_packets() {
        let dest_opt = FwOption::new("--dest", "192.168.200.21,8.8.8.8");
        let range_dest_opt = FwOption::new("--dest", "192.168.200.0-192.168.200.255,8.8.8.8");
        let range_dest_opt_miss = FwOption::new("--dest", "192.168.200.0-192.168.200.20,8.8.8.8");
        let source_opt = FwOption::new("--dest", "192.168.200.0-192.168.200.255,2.1.1.2");
        let dport_opt = FwOption::new("--dport", "2000");
        let range_dport_opt = FwOption::new("--dport", "6700:6750");
        let sport_opt_miss = FwOption::new("--sport", "6712");
        let range_sport_opt = FwOption::new("--sport", "6711:6750");
        let range_sport_opt_miss = FwOption::new("--sport", "6712:6750");
        let icmp_type_opt = FwOption::new("--icmp-type", "8");
        let wrong_icmp_type_opt = FwOption::new("--icmp-type", "7");
        let tcp_proto_opt = FwOption::new("--proto", "6");
        let icmp_proto_opt = FwOption::new("--proto", "1");

        // tcp packet
        assert!(dest_opt.matches_packet(&TCP_PACKET));
        assert!(range_dest_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&TCP_PACKET));
        assert!(source_opt.matches_packet(&TCP_PACKET));
        assert!(dport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dport_opt.matches_packet(&TCP_PACKET));
        assert!(!sport_opt_miss.matches_packet(&TCP_PACKET));
        assert!(range_sport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_sport_opt_miss.matches_packet(&TCP_PACKET));
        assert!(!icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(tcp_proto_opt.matches_packet(&TCP_PACKET));
        assert!(!icmp_proto_opt.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(!dest_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dest_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&TCP_PACKET));
        assert!(source_opt.matches_packet(&TCP_PACKET));
        assert!(!dport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_sport_opt.matches_packet(&TCP_PACKET));
        assert!(icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(!tcp_proto_opt.matches_packet(&TCP_PACKET));
        assert!(icmp_proto_opt.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(!dest_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dest_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&TCP_PACKET));
        assert!(!source_opt.matches_packet(&TCP_PACKET));
        assert!(!dport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_sport_opt.matches_packet(&TCP_PACKET));
        assert!(!icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(!tcp_proto_opt.matches_packet(&TCP_PACKET));
        assert!(!icmp_proto_opt.matches_packet(&TCP_PACKET));
    }
}
