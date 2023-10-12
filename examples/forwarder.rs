use std::collections::{HashMap, VecDeque};
use std::{env, thread};
use std::io::Write;
use std::net::TcpStream;
use std::process;
use std::time::{Duration};
use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use log::debug;

use ixy::memory::{alloc_pkt_batch, Mempool, Packet};
use ixy::*;
use ixy::dev::sniffer::{format_ipv4_address, format_ipv6_address};

// number of packets sent simultaneously by our driver
const BATCH_SIZE: usize = 1;
// number of packets in our mempool
const NUM_PACKETS: usize = 2048;
// size of our packets
const PACKET_SIZE: usize = 60;

pub fn main() {
    let mut args = env::args();
    args.next();

    let pci_addr_1 = match args.next() {
        Some(arg) => arg,
        None => {
            eprintln!("Usage: cargo run --example forwarder <pci bus id1> <pci bus id2>");
            process::exit(1);
        }
    };

    let pci_addr_2 = match args.next() {
        Some(arg) => arg,
        None => {
            eprintln!("Usage: cargo run --example forwarder <pci bus id1> <pci bus id2>");
            process::exit(1);
        }
    };

    // transmits one packet every second from the first device
    let transmitter_thread = thread::Builder::new()
        .name("transmitter".to_string())
        .spawn(move || {
            transmit(pci_addr_1);
        })
        .unwrap();

    // receives packets and writes them to the corresponding socket
    thread::Builder::new()
        .name("receiver".to_string())
        .spawn(move || {
            receive(pci_addr_2);
        })
        .unwrap();

    transmitter_thread.join();
}

// transmits one packet every second
fn transmit(pci_addr: String) {
    let mut dev = ixy_init(&pci_addr, 1, 1, 0).unwrap();

    // packet to send
    #[rustfmt::skip]
        let mut pkt_data = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,         // dst MAC
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10,         // src MAC
        0x08, 0x00,                                 // ether type: IPv4
        0x45, 0x00,                                 // Version, IHL, TOS
        ((PACKET_SIZE - 14) >> 8) as u8,            // ip len excluding ethernet, high byte
        ((PACKET_SIZE - 14) & 0xFF) as u8,          // ip len excluding ethernet, low byte
        0x00, 0x00, 0x00, 0x00,                     // id, flags, fragmentation
        0x40, 0x11, 0x00, 0x00,                     // TTL (64), protocol (UDP), checksum
        8, 8, 8, 8,                                 // src ip
        127, 0, 0, 1,                           // dst ip
        0x00, 0x08, 0x03, 0xe7,                     // src and dst ports (8 -> 999)
        ((PACKET_SIZE - 20 - 14) >> 8) as u8,       // udp len excluding ip & ethernet, high byte
        ((PACKET_SIZE - 20 - 14) & 0xFF) as u8,     // udp len excluding ip & ethernet, low byte
        0x00, 0x00,                                 // udp checksum, optional
        b'p', b'a', b'c',b'k', b'e', b't', b' '           // payload
        // rest of the payload is zero-filled because mempools guarantee empty bufs
    ];
    pkt_data[6..12].clone_from_slice(&dev.get_mac_addr());

    let pool = Mempool::allocate(NUM_PACKETS, 0).unwrap();

    // pre-fill all packet buffer in the pool with data and return them to the packet pool
    {
        let mut buffer: VecDeque<Packet> = VecDeque::with_capacity(NUM_PACKETS);

        alloc_pkt_batch(&pool, &mut buffer, NUM_PACKETS, PACKET_SIZE);

        for (p_id, p) in buffer.iter_mut().enumerate() {
            for (i, data) in pkt_data.iter().enumerate() {
                p[i] = *data;
            }
            p[49] = p_id as u8;
            let checksum = calc_ipv4_checksum(&p[14..14 + 20]);
            // Calculated checksum is little-endian; checksum field is big-endian
            p[24] = (checksum >> 8) as u8;
            p[25] = (checksum & 0xff) as u8;
        }
    }

    let mut buffer: VecDeque<Packet> = VecDeque::with_capacity(BATCH_SIZE);

    loop {
        // re-fill our packet queue with new packets to send out
        alloc_pkt_batch(&pool, &mut buffer, BATCH_SIZE, PACKET_SIZE);

        dev.tx_batch_busy_wait(0, &mut buffer);

        // wait 1 second before sending another packet
        thread::sleep(Duration::from_secs(1));
    }
}

// receives packets and writes them to the corresponding socket
fn receive(pci_addr: String) {
    let mut dev = ixy_init(&pci_addr, 1, 1, 0).unwrap();

    let mut streams: HashMap<String, TcpStream> = HashMap::new();
    loop {
        let mut buffer: VecDeque<Packet> = VecDeque::with_capacity(BATCH_SIZE);
        let num_rx = dev.rx_batch(0, &mut buffer, BATCH_SIZE);

        if num_rx > 0 {
            for packet in buffer {
                let socket = get_socket(&packet[..]);
                println!("Socket used: {}", socket);
                if !streams.contains_key(&socket) {
                    streams.insert(socket.clone(), TcpStream::connect(&socket).unwrap());
                }
                let mut stream = streams.get(&socket).unwrap();
                let payload = PacketHeaders::from_ethernet_slice(&packet[..]).unwrap().payload;
                stream.write(payload).unwrap();
            }
        }

        // wait 1 second before receiving other packets, to not poll unnecessarily
        thread::sleep(Duration::from_secs(1));
    }
}

fn get_socket(packet: &[u8]) -> String {
    if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet) {
        let ip_addr = match headers.ip.unwrap() {
            IpHeader::Version4(h, _) => {format_ipv4_address(h.destination)}
            IpHeader::Version6(h, _) => {format_ipv6_address(h.destination)}
        };
        let port = match headers.transport.unwrap() {
            TransportHeader::Udp(h) => {h.destination_port}
            TransportHeader::Tcp(h) => {h.destination_port}
            TransportHeader::Icmpv4(_) => {0}
            TransportHeader::Icmpv6(_) => {0}
        };
        return format!("{}:{}", ip_addr, port);
    }
    String::new()
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
