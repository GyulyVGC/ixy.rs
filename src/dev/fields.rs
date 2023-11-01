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

#[cfg(test)]
mod tests {
    use crate::dev::fields::{
        get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport,
    };
    use etherparse::PacketHeaders;
    use std::net::IpAddr;
    use std::str::FromStr;

    // packets are taken from wireshark sample captures available at <https://wiki.wireshark.org/SampleCaptures>
    #[rustfmt::skip]
    const TCP_PACKET: [u8;66] = [
        // ethernet header
        0x00, 0x0c, 0x29, 0x1c, 0xe3, 0x19,
        0xec, 0xf4, 0xbb, 0xd9, 0xe3, 0x7d,
        0x08, 0x00,
        // ip header
        0x45, 0x00, 0x00, 0x34, 0x1b, 0x63,
        0x40, 0x00, 0x80, 0x06, 0xcd, 0x72,
        0xc0, 0xa8, 0xc8, 0x87,
        0xc0, 0xa8, 0xc8, 0x15,
        // tcp header
        0x1a, 0x37, 0x07, 0xd0, 0xdd, 0x6a,
        0xbb, 0x2a, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x02, 0xfa, 0xf0, 0x12, 0x15,
        0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x01, 0x03, 0x03, 0x08, 0x01, 0x01,
        0x04, 0x02
    ];

    #[rustfmt::skip]
    const ICMP_PACKET: [u8;50] = [
        // ethernet header
        0x00, 0x0c, 0x29, 0x1c, 0xe3, 0x19,
        0xec, 0xf4, 0xbb, 0xd9, 0xe3, 0x7d,
        0x08, 0x00,
        // ip header
        0x45, 0x00, 0x00, 0x34, 0x1b, 0x63,
        0x40, 0x00, 0x80, 0x01, 0xcd, 0x72,
        0x02, 0x01, 0x01, 0x02,
        0x02, 0x01, 0x01, 0x01,
        // icmp header
        0x08, 0x00, 0x4d, 0x71, 0x13, 0xc2,
        0x00, 0x01, 0x14, 0x2b, 0xd2, 0x59,
        0x00, 0x00, 0x00, 0x00
    ];

    #[rustfmt::skip]
    const ARP_PACKET: [u8;42] = [
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01,         // dst MAC
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02,         // src MAC
        0x08, 0x06,                                 // ether type: ARP
        0x00, 0x01,                                 // HTYPE: ethernet
        0x08, 0x00,                                 // PTYPE: IPv4
        6,                                          // HLEN: 6 bytes for ethernet
        4,                                          // PLEN: 4 bytes for IPv4
        0x00, 0x02,                                 // operation: 2 is ARP reply
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01,         // sender MAC
        192, 168, 1, 251,                           // sender IP
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02,         // target MAC
        192, 168, 1, 1,                             // target IP
    ];

    #[test]
    fn test_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let ip_header = headers.ip;
        let transport_header = headers.transport;
        assert_eq!(get_proto(ip_header.clone()), Some(6)); // tcp
        assert_eq!(
            get_source(ip_header.clone()),
            Some(IpAddr::from_str("192.168.200.135").unwrap())
        );
        assert_eq!(
            get_dest(ip_header),
            Some(IpAddr::from_str("192.168.200.21").unwrap())
        );
        assert_eq!(get_icmp_type(transport_header.clone()), None);
        assert_eq!(get_sport(transport_header.clone()), Some(6711));
        assert_eq!(get_dport(transport_header), Some(2000));
    }

    #[test]
    fn test_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let ip_header = headers.ip;
        let transport_header = headers.transport;
        assert_eq!(get_proto(ip_header.clone()), Some(1)); // icmp
        assert_eq!(
            get_source(ip_header.clone()),
            Some(IpAddr::from_str("2.1.1.2").unwrap())
        );
        assert_eq!(
            get_dest(ip_header),
            Some(IpAddr::from_str("2.1.1.1").unwrap())
        );
        assert_eq!(get_icmp_type(transport_header.clone()), Some(8)); // echo request
        assert_eq!(get_sport(transport_header.clone()), None);
        assert_eq!(get_dport(transport_header), None);
    }

    #[test]
    fn test_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let ip_header = headers.ip;
        let transport_header = headers.transport;
        assert_eq!(get_proto(ip_header.clone()), None);
        assert_eq!(get_source(ip_header.clone()), None);
        assert_eq!(get_dest(ip_header), None);
        assert_eq!(get_icmp_type(transport_header.clone()), None);
        assert_eq!(get_sport(transport_header.clone()), None);
        assert_eq!(get_dport(transport_header), None);
    }
}
