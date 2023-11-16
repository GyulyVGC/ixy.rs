use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use byteorder::{WriteBytesExt, LE};
use etherparse::{Icmpv4Type, IpHeader, PacketHeaders, TransportHeader};
use ixy::memory::{alloc_pkt_batch, Mempool, Packet};
use ixy::*;

const BATCH_SIZE: usize = 32;

const MY_IP: [u8; 4] = [192, 168, 1, 251];

pub fn main() -> Result<(), io::Error> {
    let mut args = env::args().skip(1);

    let (pci_addr, output_file) = match (args.next(), args.next()) {
        (Some(pci_addr), Some(output_file)) => (pci_addr, output_file),
        _ => {
            eprintln!("Usage: cargo run --example pcap <pci bus id> <output file> [n packets]");
            process::exit(1);
        }
    };

    let mut pcap = File::create(output_file)?;

    // pcap header
    pcap.write_u32::<LE>(0xa1b2_c3d4)?; // magic_number
    pcap.write_u16::<LE>(2)?; // version_major
    pcap.write_u16::<LE>(4)?; // version_minor
    pcap.write_i32::<LE>(0)?; // thiszone
    pcap.write_u32::<LE>(0)?; // sigfigs
    pcap.write_u32::<LE>(65535)?; // snaplen
    pcap.write_u32::<LE>(1)?; // network: Ethernet

    let mut dev = ixy_init(&pci_addr, 1, 1, 0).unwrap();

    println!("MAC address: {:02X?}", dev.get_mac_addr());

    // println!("Setting MAC address to BE:AE:F0:42:E7:B3");
    // dev.set_mac_addr([0xbe, 0xae, 0xf0, 0x42, 0xe7, 0xb3]);
    // println!("MAC address: {:02X?}", dev.get_mac_addr());

    let mut buffer: VecDeque<Packet> = VecDeque::with_capacity(BATCH_SIZE);
    loop {
        dev.rx_batch(0, &mut buffer, BATCH_SIZE);
        let time = SystemTime::now();
        let time = time.duration_since(UNIX_EPOCH).unwrap();

        for packet in buffer.drain(..) {
            // pcap record header
            pcap.write_u32::<LE>(time.as_secs() as u32)?; // ts_sec
            pcap.write_u32::<LE>(time.subsec_millis())?; // ts_usec
            pcap.write_u32::<LE>(packet.len() as u32)?; // incl_len
            pcap.write_u32::<LE>(packet.len() as u32)?; // orig_len

            pcap.write_all(&packet)?;

            handle_arp(&packet[..], &mut dev);
            handle_ipv4_ping(&packet, &mut dev);
        }
    }
}

pub fn handle_arp(pkt_data: &[u8], dev: &mut Box<dyn IxyDevice>) {
    if let Ok(headers) = PacketHeaders::from_ethernet_slice(pkt_data) {
        if let Some(link) = headers.link {
            if link.ether_type.eq(&etherparse::ether_type::ARP) // ARP
                && headers.payload[7] == 1 // ARP request
                && headers.payload[24..28].eq(&MY_IP)
            {
                send_arp_reply(pkt_data, dev);
            }
        }
    }
}

pub fn handle_ipv4_ping(pkt_data: &[u8], dev: &mut Box<dyn IxyDevice>) {
    if let Ok(headers) = PacketHeaders::from_ethernet_slice(pkt_data) {
        if let Some(IpHeader::Version4(h, _)) = headers.ip {
            if h.destination.eq(&MY_IP) {
                if let Some(TransportHeader::Icmpv4(h)) = headers.transport {
                    match h.icmp_type {
                        Icmpv4Type::EchoRequest(_) => {
                            // echo request
                            send_echo_reply(pkt_data, dev);
                        }
                        _ => return,
                    }
                }
            }
        }
    }
}

fn send_arp_reply(arp_request: &[u8], dev: &mut Box<dyn IxyDevice>) {
    #[rustfmt::skip]
    let mut pkt_data = [
        // ethernet header
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // dst MAC (will be set later)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // src MAC (will be set later)
        0x08, 0x06,                                 // ether type: ARP
        // arp payload
        0x00, 0x01,                                 // HTYPE: ethernet
        0x08, 0x00,                                 // PTYPE: IPv4
        6,                                          // HLEN: 6 bytes for ethernet
        4,                                          // PLEN: 4 bytes for IPv4
        0x00, 0x02,                                 // operation: 2 is ARP reply
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // sender MAC (will be set later)
        192, 168, 1, 251,                           // sender IP (for the moment it's static)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // target MAC (will be set later)
        0, 0, 0, 0,                                 // target IP (will be set later)
    ];

    // set destination MAC to source MAC address of the ARP request
    pkt_data[0..6].clone_from_slice(&arp_request[6..12]);
    // set source MAC to MAC address of this device
    pkt_data[6..12].clone_from_slice(&dev.get_mac_addr());
    // set sender MAC to MAC address of this device
    pkt_data[22..28].clone_from_slice(&dev.get_mac_addr());
    // set target MAC to source MAC address of the ARP request
    pkt_data[32..38].clone_from_slice(&arp_request[6..12]);
    // set the target IP to source IP address of the ARP request
    pkt_data[38..42].clone_from_slice(&arp_request[28..32]);

    let pool = Mempool::allocate(1, 0).unwrap();
    // pre-fill all packet buffer in the pool with data and return them to the packet pool
    {
        let mut buffer: VecDeque<Packet> = VecDeque::with_capacity(1);
        alloc_pkt_batch(&pool, &mut buffer, 1, 42);
        for p in buffer.iter_mut() {
            for (i, data) in pkt_data.iter().enumerate() {
                p[i] = *data;
            }
        }
    }
    let mut buffer: VecDeque<Packet> = VecDeque::with_capacity(BATCH_SIZE);
    alloc_pkt_batch(&pool, &mut buffer, 1, 42);
    dev.tx_batch_busy_wait(0, &mut buffer);
}

fn send_echo_reply(ping: &[u8], dev: &mut Box<dyn IxyDevice>) {
    #[rustfmt::skip]
    let mut pkt_data = [
        // ethernet header
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // dst MAC (will be set later)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // src MAC (will be set later)
        0x08, 0x00,                                 // ether type: IPv4
        // ipv4 header
        0x45, 0x00,                                 // version, header length, congestion
        0x00, 0x00,                                 // length (will be set later)
        0x00, 0x00, 0x00, 0x00,                     // identification, fragmentation
        0x40, 0x01,                                 // ttl and protocol
        0x00, 0x00,                                 // header checksum (will be set later)
        0x00, 0x00, 0x00, 0x00,                     // source (will be set later)
        0x00, 0x00, 0x00, 0x00,                     // dest (will be set later)
        // icmp header and payload
        0x00, 0x00,                                 // echo reply
        0x00, 0x00,                                 // checksum (will be set later)
        // rest of the packet is the same as the ping and will be copied from it
    ];

    // destination MAC
    pkt_data[0..6].clone_from_slice(&ping[6..12]); // source MAC of the ping

    // source MAC
    pkt_data[6..12].clone_from_slice(&dev.get_mac_addr()); // my MAC

    // length
    pkt_data[16..18].clone_from_slice(&ping[16..18]); // equivalent to ping length

    // source
    pkt_data[26..30].clone_from_slice(&MY_IP); // my IP

    // dest
    pkt_data[30..34].clone_from_slice(&ping[26..30]); // sender of the ping

    // ip header checksum
    let ip_checksum = calc_ipv4_checksum(&pkt_data[14..14 + 20]);
    pkt_data[24] = (ip_checksum >> 8) as u8; // calculated checksum is little-endian; checksum field is big-endian
    pkt_data[25] = (ip_checksum & 0xff) as u8; // calculated checksum is little-endian; checksum field is big-endian

    // icmp checksum
    pkt_data[36] = ping[36] | 0x8;
    pkt_data[37].clone_from(&ping[37]);

    // rest of the packet
    let pkt_data_final = &[&pkt_data[..], &ping[38..]].concat()[..];

    let pool = Mempool::allocate(1, 0).unwrap();
    // pre-fill all packet buffer in the pool with data and return them to the packet pool
    {
        let mut buffer: VecDeque<Packet> = VecDeque::with_capacity(1);
        alloc_pkt_batch(&pool, &mut buffer, 1, 42);
        for p in buffer.iter_mut() {
            for (i, data) in pkt_data_final.iter().enumerate() {
                p[i] = *data;
            }
        }
    }
    let mut buffer: VecDeque<Packet> = VecDeque::with_capacity(BATCH_SIZE);
    alloc_pkt_batch(&pool, &mut buffer, 1, ping.len());
    dev.tx_batch_busy_wait(0, &mut buffer);
}

fn calc_ipv4_checksum(ipv4_header: &[u8]) -> u16 {
    assert_eq!(ipv4_header.len() % 2, 0);
    let mut checksum = 0;
    for i in 0..ipv4_header.len() / 2 {
        if i == 5 {
            // Assume checksum field is set to 0
            continue;
        }
        checksum += (u32::from(ipv4_header[i * 2]) << 8) + u32::from(ipv4_header[i * 2 + 1]);
        if checksum > 0xffff {
            checksum = (checksum & 0xffff) + 1;
        }
    }
    !(checksum as u16)
}
