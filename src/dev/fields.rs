use etherparse::{IpHeader, TransportHeader};
use std::net::IpAddr;

/// Extract header fields

pub fn get_source(ip_header: Option<IpHeader>) -> Option<IpAddr> {
    if let Some(ip) = ip_header {
        match ip {
            IpHeader::Version4(h, _) => Some(IpAddr::from(h.source)),
            IpHeader::Version6(h, _) => Some(IpAddr::from(h.source)),
        }
    } else {
        None
    }
}

pub fn get_dest(ip_header: Option<IpHeader>) -> Option<IpAddr> {
    if let Some(ip) = ip_header {
        match ip {
            IpHeader::Version4(h, _) => Some(IpAddr::from(h.destination)),
            IpHeader::Version6(h, _) => Some(IpAddr::from(h.destination)),
        }
    } else {
        None
    }
}

pub fn get_sport(transport_header: Option<TransportHeader>) -> Option<u16> {
    if let Some(transport) = transport_header {
        match transport {
            TransportHeader::Tcp(h) => Some(h.source_port),
            TransportHeader::Udp(h) => Some(h.source_port),
            TransportHeader::Icmpv4(_) | TransportHeader::Icmpv6(_) => None,
        }
    } else {
        None
    }
}

pub fn get_dport(transport_header: Option<TransportHeader>) -> Option<u16> {
    if let Some(transport) = transport_header {
        match transport {
            TransportHeader::Tcp(h) => Some(h.destination_port),
            TransportHeader::Udp(h) => Some(h.destination_port),
            TransportHeader::Icmpv4(_) | TransportHeader::Icmpv6(_) => None,
        }
    } else {
        None
    }
}

pub fn get_proto(ip_header: Option<IpHeader>) -> Option<u8> {
    if let Some(ip) = ip_header {
        match ip {
            IpHeader::Version4(h, _) => Some(h.protocol),
            IpHeader::Version6(h, _) => Some(h.next_header),
        }
    } else {
        None
    }
}

pub fn get_icmp_type(transport_header: Option<TransportHeader>) -> Option<u8> {
    if let Some(transport) = transport_header {
        match transport {
            TransportHeader::Icmpv4(h) => Some(*h.to_bytes().first().unwrap()),
            TransportHeader::Icmpv6(h) => Some(*h.to_bytes().first().unwrap()),
            TransportHeader::Tcp(_) | TransportHeader::Udp(_) => None,
        }
    } else {
        None
    }
}
