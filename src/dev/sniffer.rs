// fn format_mac_address(mac_dec: [u8; 6]) -> String {
//     let mut mac_hex = String::new();
//     for n in &mac_dec {
//         mac_hex.push_str(&format!("{n:02x}:"));
//     }
//     mac_hex.pop();
//     mac_hex
// }

pub fn format_ipv4_address(address: [u8; 4]) -> String {
    format!("{address:?}")
        .replace('[', "")
        .replace(']', "")
        .replace(',', ".")
        .replace(' ', "")
}

/// Function to convert a long decimal ipv6 address to a
/// shorter compressed ipv6 address
///
/// # Arguments
///
/// * `ipv6_long` - Contains the 16 integer composing the not compressed decimal ipv6 address
pub fn format_ipv6_address(ipv6_long: [u8; 16]) -> String {
    //from hex to dec, paying attention to the correct number of digits
    let mut ipv6_hex = String::new();
    for i in 0..=15 {
        //even: first byte of the group
        if i % 2 == 0 {
            if *ipv6_long.get(i).unwrap() == 0 {
                continue;
            }
            ipv6_hex.push_str(&format!("{:x}", ipv6_long.get(i).unwrap()));
        }
        //odd: second byte of the group
        else if *ipv6_long.get(i - 1).unwrap() == 0 {
            ipv6_hex.push_str(&format!("{:x}:", ipv6_long.get(i).unwrap()));
        } else {
            ipv6_hex.push_str(&format!("{:02x}:", ipv6_long.get(i).unwrap()));
        }
    }
    ipv6_hex.pop();

    // search for the longest zero sequence in the ipv6 address
    let mut to_compress: Vec<&str> = ipv6_hex.split(':').collect();
    let mut longest_zero_sequence = 0; // max number of consecutive zeros
    let mut longest_zero_sequence_start = 0; // first index of the longest sequence of zeros
    let mut current_zero_sequence = 0;
    let mut current_zero_sequence_start = 0;
    let mut i = 0;
    for s in to_compress.clone() {
        if s.eq("0") {
            if current_zero_sequence == 0 {
                current_zero_sequence_start = i;
            }
            current_zero_sequence += 1;
        } else if current_zero_sequence != 0 {
            if current_zero_sequence > longest_zero_sequence {
                longest_zero_sequence = current_zero_sequence;
                longest_zero_sequence_start = current_zero_sequence_start;
            }
            current_zero_sequence = 0;
        }
        i += 1;
    }
    if current_zero_sequence != 0 {
        // to catch consecutive zeros at the end
        if current_zero_sequence > longest_zero_sequence {
            longest_zero_sequence = current_zero_sequence;
            longest_zero_sequence_start = current_zero_sequence_start;
        }
    }
    if longest_zero_sequence < 2 {
        // no compression needed
        return ipv6_hex;
    }

    //from longest sequence of consecutive zeros to '::'
    let mut ipv6_hex_compressed = String::new();
    for _ in 0..longest_zero_sequence {
        to_compress.remove(longest_zero_sequence_start);
    }
    i = 0;
    if longest_zero_sequence_start == 0 {
        ipv6_hex_compressed.push_str("::");
    }
    for s in to_compress {
        ipv6_hex_compressed.push_str(s);
        ipv6_hex_compressed.push(':');
        i += 1;
        if i == longest_zero_sequence_start {
            ipv6_hex_compressed.push(':');
        }
    }
    if ipv6_hex_compressed.ends_with("::") {
        return ipv6_hex_compressed;
    }
    ipv6_hex_compressed.pop();

    ipv6_hex_compressed
}
