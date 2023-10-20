use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use byteorder::{WriteBytesExt, LE};
use colored::Colorize;
use etherparse::PacketHeaders;
use ixy::memory::{alloc_pkt_batch, Mempool, Packet};
use ixy::*;
use simple_logger::SimpleLogger;

const BATCH_SIZE: usize = 32;

pub fn main() -> Result<(), io::Error> {
    SimpleLogger::new().init().unwrap();

    let mut args = env::args().skip(1);

    let (pci_addr, output_file) = match (args.next(), args.next()) {
        (Some(pci_addr), Some(output_file)) => (pci_addr, output_file),
        _ => {
            eprintln!("Usage: cargo run --example pcap <pci bus id> <output file> [n packets]");
            process::exit(1);
        }
    };

    let mut n_packets: Option<usize> = args
        .next()
        .map(|n| n.parse().expect("failed to parse n packets"));
    if let Some(n) = n_packets {
        println!("Capturing {} packets...", n);
    } else {
        println!("Capturing packets...");
    }

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
    while n_packets != Some(0) {
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

            n_packets = n_packets.map(|n| n - 1);
            if n_packets == Some(0) {
                break;
            }
        }
    }

    Ok(())
}

pub fn handle_arp(pkt_data: &[u8], dev: &mut Box<dyn IxyDevice>) {
    if let Ok(headers) = PacketHeaders::from_ethernet_slice(pkt_data) {
        if let Some(link) = headers.link {
            if link.ether_type.eq(&etherparse::ether_type::ARP) {
                // check if ether type is 0x0806 (ARP)
                let target_ip = &headers.payload[24..28];
                if headers.payload[7] == 1 && target_ip.eq(&[192, 168, 1, 251]) {
                    println!("{}", "Found an ARP packet with my IP!".color("green"));
                    println!("{}", format!("Target IP: {:?}", target_ip).color("green"));
                    println!(
                        "{}",
                        "Producing the corresponding ARP reply...".color("green")
                    );
                    send_arp_reply(pkt_data, dev);
                }
            }
        }
    }
}

fn send_arp_reply(arp_request: &[u8], dev: &mut Box<dyn IxyDevice>) {
    #[rustfmt::skip]
    let mut pkt_data = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // dst MAC (will be set later)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // src MAC (will be set later)
        0x08, 0x06,                                 // ether type: ARP
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
