use std::collections::VecDeque;
use std::env;
use std::process;
use std::time::Instant;

use ixy::memory::Packet;
use ixy::*;
use simple_logger::SimpleLogger;

const BATCH_SIZE: usize = 32;

pub fn main() {
    SimpleLogger::new().init().unwrap();

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

    let mut dev1 = ixy_init(&pci_addr_1, 1, 1, 0).unwrap();
    let mut dev2 = ixy_init(&pci_addr_2, 1, 1, 0).unwrap();

    let mut buffer: VecDeque<Packet> = VecDeque::with_capacity(BATCH_SIZE);

    loop {
        forward(&mut buffer, &mut *dev1, &mut *dev2);
    }
}

fn forward(
    buffer: &mut VecDeque<Packet>,
    rx_dev: &mut dyn IxyDevice,
    tx_dev: &mut dyn IxyDevice,
) {
    let num_rx = rx_dev.rx_batch(0, buffer, BATCH_SIZE);

    if num_rx > 0 {
        tx_dev.tx_batch_busy_wait(0, buffer);
    }
}
