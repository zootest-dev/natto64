//! Internet-checksum calculation helpers.

/// Fold a 32-bit accumulator into a 16-bit one's-complement sum.
#[inline]
fn fold_sum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum as u16
}

#[inline]
fn checksum16_with_seed(data: &[u8], mut sum: u32) -> u16 {
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(u32::from(word));
    }

    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([last, 0])));
    }

    fold_sum(sum)
}

/// Returns the folded one's-complement sum over `data`.
///
/// This function does **not** apply the final bitwise complement. That makes
/// verification convenient: if a checksum field has been filled correctly,
/// recomputing over the full material yields `0xFFFF`.
pub fn checksum16(data: &[u8]) -> u16 {
    checksum16_with_seed(data, 0)
}

/// Compute the IPv4 header checksum for a 20-byte IPv4 header.
///
/// `hdr` must have `hdr[10..12]` set to zero before calling.
pub fn ipv4_header_checksum_20b(hdr: &[u8; 20]) -> u16 {
    !checksum16(hdr)
}

/// Compute TCP checksum over IPv4 pseudo-header + TCP segment.
///
/// `src_v4_be` and `dst_v4_be` are IPv4 addresses in network byte order.
/// The TCP checksum field bytes (`tcp[16]` and `tcp[17]`) are treated as zero
/// while accumulating (if present).
pub fn tcp_checksum_ipv4(src_v4_be: u32, dst_v4_be: u32, tcp: &[u8]) -> u16 {
    let src = src_v4_be.to_be_bytes();
    let dst = dst_v4_be.to_be_bytes();
    let tcp_len = tcp.len() as u16;

    let mut sum = 0u32;
    sum = u32::from(checksum16_with_seed(&src, sum));
    sum = u32::from(checksum16_with_seed(&dst, sum));
    sum = sum.wrapping_add(6); // TCP protocol number
    sum = sum.wrapping_add(u32::from(tcp_len));

    let mut i = 0usize;
    while i + 1 < tcp.len() {
        let hi = if i == 16 { 0 } else { tcp[i] };
        let lo = if i + 1 == 17 { 0 } else { tcp[i + 1] };
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hi, lo])));
        i += 2;
    }

    if i < tcp.len() {
        let last = if i == 16 { 0 } else { tcp[i] };
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([last, 0])));
    }

    let checksum = !fold_sum(sum);
    if checksum == 0 { 0xffff } else { checksum }
}

/// Compute TCP checksum over IPv6 pseudo-header + TCP segment.
///
/// `src_v6` and `dst_v6` are IPv6 addresses in network byte order.
/// The TCP checksum field bytes (`tcp[16]` and `tcp[17]`) are treated as zero
/// while accumulating (if present).
pub fn tcp_checksum_ipv6(src_v6: &[u8; 16], dst_v6: &[u8; 16], tcp: &[u8]) -> u16 {
    let tcp_len = tcp.len() as u32;

    let mut sum = 0u32;
    sum = u32::from(checksum16_with_seed(src_v6, sum));
    sum = u32::from(checksum16_with_seed(dst_v6, sum));
    sum = sum.wrapping_add((tcp_len >> 16) & 0xffff);
    sum = sum.wrapping_add(tcp_len & 0xffff);
    sum = sum.wrapping_add(6); // Next header: TCP

    let mut i = 0usize;
    while i + 1 < tcp.len() {
        let hi = if i == 16 { 0 } else { tcp[i] };
        let lo = if i + 1 == 17 { 0 } else { tcp[i + 1] };
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hi, lo])));
        i += 2;
    }

    if i < tcp.len() {
        let last = if i == 16 { 0 } else { tcp[i] };
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([last, 0])));
    }

    let checksum = !fold_sum(sum);
    if checksum == 0 { 0xffff } else { checksum }
}

/// Compute UDP checksum over IPv4 pseudo-header + UDP datagram.
///
/// `src_v4_be` and `dst_v4_be` are IPv4 addresses in network byte order.
/// The UDP checksum field bytes (`udp[6]` and `udp[7]`) are treated as zero
/// while accumulating (if present).
pub fn udp_checksum_ipv4(src_v4_be: u32, dst_v4_be: u32, udp: &[u8]) -> u16 {
    let src = src_v4_be.to_be_bytes();
    let dst = dst_v4_be.to_be_bytes();
    let udp_len = udp.len() as u16;

    let mut sum = 0u32;
    sum = u32::from(checksum16_with_seed(&src, sum));
    sum = u32::from(checksum16_with_seed(&dst, sum));
    sum = sum.wrapping_add(17); // UDP protocol number
    sum = sum.wrapping_add(u32::from(udp_len));

    let mut i = 0usize;
    while i + 1 < udp.len() {
        let hi = if i == 6 { 0 } else { udp[i] };
        let lo = if i + 1 == 7 { 0 } else { udp[i + 1] };
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hi, lo])));
        i += 2;
    }

    if i < udp.len() {
        let last = if i == 6 { 0 } else { udp[i] };
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([last, 0])));
    }

    let checksum = !fold_sum(sum);
    if checksum == 0 { 0xffff } else { checksum }
}

/// Compute UDP checksum over IPv6 pseudo-header + UDP datagram.
///
/// `src_v6` and `dst_v6` are IPv6 addresses in network byte order.
/// The UDP checksum field bytes (`udp[6]` and `udp[7]`) are treated as zero
/// while accumulating (if present).
pub fn udp_checksum_ipv6(src_v6: &[u8; 16], dst_v6: &[u8; 16], udp: &[u8]) -> u16 {
    let udp_len = udp.len() as u32;

    let mut sum = 0u32;
    sum = u32::from(checksum16_with_seed(src_v6, sum));
    sum = u32::from(checksum16_with_seed(dst_v6, sum));
    sum = sum.wrapping_add((udp_len >> 16) & 0xffff);
    sum = sum.wrapping_add(udp_len & 0xffff);
    sum = sum.wrapping_add(17); // Next header: UDP

    let mut i = 0usize;
    while i + 1 < udp.len() {
        let hi = if i == 6 { 0 } else { udp[i] };
        let lo = if i + 1 == 7 { 0 } else { udp[i + 1] };
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hi, lo])));
        i += 2;
    }

    if i < udp.len() {
        let last = if i == 6 { 0 } else { udp[i] };
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([last, 0])));
    }

    let checksum = !fold_sum(sum);
    if checksum == 0 { 0xffff } else { checksum }
}

#[cfg(test)]
mod tests {
    use super::{
        checksum16, ipv4_header_checksum_20b, tcp_checksum_ipv4, tcp_checksum_ipv6,
        udp_checksum_ipv4, udp_checksum_ipv6,
    };

    fn verify_ones_complement_ok(sum: u16) {
        assert_eq!(sum, 0xFFFF);
    }

    fn pseudo_sum(src: u32, dst: u32, tcp_len: usize) -> u32 {
        let src = src.to_be_bytes();
        let dst = dst.to_be_bytes();

        let mut sum = 0u32;
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[0], src[1]])));
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[2], src[3]])));
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[0], dst[1]])));
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[2], dst[3]])));
        sum = sum.wrapping_add(6);
        sum.wrapping_add(tcp_len as u32)
    }

    fn pseudo_sum_udp(src: u32, dst: u32, udp_len: usize) -> u32 {
        let src = src.to_be_bytes();
        let dst = dst.to_be_bytes();

        let mut sum = 0u32;
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[0], src[1]])));
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[2], src[3]])));
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[0], dst[1]])));
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[2], dst[3]])));
        sum = sum.wrapping_add(17);
        sum.wrapping_add(udp_len as u32)
    }

    fn pseudo_sum_v6(src: &[u8; 16], dst: &[u8; 16], tcp_len: usize) -> u32 {
        let mut sum = 0u32;
        for i in (0..16).step_by(2) {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[i], src[i + 1]])));
        }
        for i in (0..16).step_by(2) {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[i], dst[i + 1]])));
        }
        let tcp_len = tcp_len as u32;
        sum = sum.wrapping_add((tcp_len >> 16) & 0xffff);
        sum = sum.wrapping_add(tcp_len & 0xffff);
        sum.wrapping_add(6)
    }

    fn pseudo_sum_v6_udp(src: &[u8; 16], dst: &[u8; 16], udp_len: usize) -> u32 {
        let mut sum = 0u32;
        for i in (0..16).step_by(2) {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[i], src[i + 1]])));
        }
        for i in (0..16).step_by(2) {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[i], dst[i + 1]])));
        }
        let udp_len = udp_len as u32;
        sum = sum.wrapping_add((udp_len >> 16) & 0xffff);
        sum = sum.wrapping_add(udp_len & 0xffff);
        sum.wrapping_add(17)
    }

    fn checksum16_with_seed_for_test(data: &[u8], mut sum: u32) -> u16 {
        let mut chunks = data.chunks_exact(2);
        for chunk in &mut chunks {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([last, 0])));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum as u16
    }

    #[test]
    fn ipv4_header_checksum_known_property() {
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45;
        hdr[2..4].copy_from_slice(&40u16.to_be_bytes());
        hdr[8] = 64;
        hdr[9] = 6;
        hdr[12..16].copy_from_slice(&[192, 0, 2, 1]);
        hdr[16..20].copy_from_slice(&[198, 51, 100, 2]);

        let checksum = ipv4_header_checksum_20b(&hdr);
        hdr[10..12].copy_from_slice(&checksum.to_be_bytes());

        verify_ones_complement_ok(checksum16(&hdr));
    }

    #[test]
    fn tcp_checksum_zeroes_field() {
        let src = u32::from_be_bytes([203, 0, 113, 10]);
        let dst = u32::from_be_bytes([192, 0, 2, 80]);

        let mut tcp = [0u8; 20];
        tcp[12] = 0x50;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());
        tcp[16] = 0x12;
        tcp[17] = 0x34;

        let csum_special = tcp_checksum_ipv4(src, dst, &tcp);

        let mut tcp_zeroed = tcp;
        tcp_zeroed[16] = 0;
        tcp_zeroed[17] = 0;
        let mut sum = pseudo_sum(src, dst, tcp_zeroed.len());
        sum = u32::from(checksum16_with_seed_for_test(&tcp_zeroed, sum));
        let csum_reference = !sum as u16;

        assert_eq!(csum_special, csum_reference);
    }

    #[test]
    fn tcp_checksum_odd_length_payload_property() {
        let src = u32::from_be_bytes([203, 0, 113, 10]);
        let dst = u32::from_be_bytes([198, 51, 100, 9]);

        let mut tcp = [0u8; 21];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        tcp[20] = 0xab;

        let checksum = tcp_checksum_ipv4(src, dst, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        let sum = checksum16_with_seed_for_test(&tcp, pseudo_sum(src, dst, tcp.len()));
        verify_ones_complement_ok(sum);
    }

    #[test]
    fn tcp_checksum_small_payload_property() {
        let src = u32::from_be_bytes([203, 0, 113, 10]);
        let dst = u32::from_be_bytes([198, 51, 100, 10]);

        let mut tcp = [0u8; 52];
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        for i in 0..32 {
            tcp[20 + i] = i as u8;
        }

        let checksum = tcp_checksum_ipv4(src, dst, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        let sum = checksum16_with_seed_for_test(&tcp, pseudo_sum(src, dst, tcp.len()));
        verify_ones_complement_ok(sum);
    }

    #[test]
    fn tcp_checksum_ipv6_property() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 1];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 2];

        let mut tcp = [0u8; 36];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        tcp[16] = 0xaa;
        tcp[17] = 0xbb;
        for i in 0..16 {
            tcp[20 + i] = i as u8;
        }

        let checksum = tcp_checksum_ipv6(&src, &dst, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        let sum = checksum16_with_seed_for_test(&tcp, pseudo_sum_v6(&src, &dst, tcp.len()));
        verify_ones_complement_ok(sum);
    }

    #[test]
    fn tcp_checksum_ipv6_odd_length_payload_property() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 7];

        let mut tcp = [0u8; 21];
        tcp[12] = 0x50;
        tcp[13] = 0x10;
        tcp[20] = 0xcc;

        let checksum = tcp_checksum_ipv6(&src, &dst, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        let sum = checksum16_with_seed_for_test(&tcp, pseudo_sum_v6(&src, &dst, tcp.len()));
        verify_ones_complement_ok(sum);
    }

    #[test]
    fn tcp_checksum_ipv6_short_slices_do_not_panic() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 8];

        for len in 0..18 {
            let tcp = [0x33u8; 17];
            let value = tcp_checksum_ipv6(&src, &dst, &tcp[..len]);
            assert_ne!(value, 0);
        }
    }

    #[test]
    fn tcp_checksum_ipv4_golden_vectors_and_verification_property() {
        let src = u32::from_be_bytes([203, 0, 113, 10]);
        let dst = u32::from_be_bytes([198, 51, 100, 10]);

        for (payload_len, expected) in [(0usize, 0x0790u16), (1, 0x068Fu16), (32, 0x245Du16)] {
            let seg_len = 20 + payload_len;
            let mut tcp = [0u8; 52];
            tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
            tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = 0x18;
            tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());
            for i in 0..payload_len {
                tcp[20 + i] = (i as u8).wrapping_mul(3).wrapping_add(1);
            }

            let checksum = tcp_checksum_ipv4(src, dst, &tcp[..seg_len]);
            assert_eq!(checksum, expected);

            tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
            let folded =
                checksum16_with_seed_for_test(&tcp[..seg_len], pseudo_sum(src, dst, seg_len));
            verify_ones_complement_ok(folded);
        }
    }

    #[test]
    fn tcp_checksum_ipv6_golden_vectors_and_verification_property() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 1];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 2];

        for (payload_len, expected) in [(0usize, 0x6359u16), (1, 0x6457u16), (32, 0x543Au16)] {
            let seg_len = 20 + payload_len;
            let mut tcp = [0u8; 52];
            tcp[0..2].copy_from_slice(&54321u16.to_be_bytes());
            tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = 0x10;
            tcp[14..16].copy_from_slice(&8192u16.to_be_bytes());
            for i in 0..payload_len {
                tcp[20 + i] = 255u8.wrapping_sub(i as u8);
            }

            let checksum = tcp_checksum_ipv6(&src, &dst, &tcp[..seg_len]);
            assert_eq!(checksum, expected);

            tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
            let folded =
                checksum16_with_seed_for_test(&tcp[..seg_len], pseudo_sum_v6(&src, &dst, seg_len));
            verify_ones_complement_ok(folded);
        }
    }

    #[test]
    fn tcp_checksum_short_slices_do_not_panic() {
        let src = u32::from_be_bytes([203, 0, 113, 10]);
        let dst = u32::from_be_bytes([198, 51, 100, 11]);

        for len in 0..18 {
            let tcp = [0x5au8; 17];
            let value = tcp_checksum_ipv4(src, dst, &tcp[..len]);
            assert_ne!(value, 0);
        }
    }

    #[test]
    fn udp_checksum_zeroes_field_ipv4() {
        let src = u32::from_be_bytes([203, 0, 113, 10]);
        let dst = u32::from_be_bytes([192, 0, 2, 80]);

        let mut udp = [0u8; 12];
        let udp_len = udp.len() as u16;
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp[6] = 0x12;
        udp[7] = 0x34;

        let csum_special = udp_checksum_ipv4(src, dst, &udp);

        let mut udp_zeroed = udp;
        udp_zeroed[6] = 0;
        udp_zeroed[7] = 0;
        let mut sum = pseudo_sum_udp(src, dst, udp_zeroed.len());
        sum = u32::from(checksum16_with_seed_for_test(&udp_zeroed, sum));
        let csum_reference = !sum as u16;

        assert_eq!(csum_special, csum_reference);
    }

    #[test]
    fn udp_checksum_odd_length_payload_property_ipv4() {
        let src = u32::from_be_bytes([203, 0, 113, 10]);
        let dst = u32::from_be_bytes([198, 51, 100, 9]);

        let mut udp = [0u8; 13];
        udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        udp[2..4].copy_from_slice(&80u16.to_be_bytes());
        let udp_len = udp.len() as u16;
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp[12] = 0xab;

        let checksum = udp_checksum_ipv4(src, dst, &udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());

        let sum = checksum16_with_seed_for_test(&udp, pseudo_sum_udp(src, dst, udp.len()));
        verify_ones_complement_ok(sum);
    }

    #[test]
    fn udp_checksum_small_payload_property_ipv4() {
        let src = u32::from_be_bytes([203, 0, 113, 10]);
        let dst = u32::from_be_bytes([198, 51, 100, 10]);

        let mut udp = [0u8; 40];
        udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        udp[2..4].copy_from_slice(&443u16.to_be_bytes());
        let udp_len = udp.len() as u16;
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        for i in 0..32 {
            udp[8 + i] = i as u8;
        }

        let checksum = udp_checksum_ipv4(src, dst, &udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());

        let sum = checksum16_with_seed_for_test(&udp, pseudo_sum_udp(src, dst, udp.len()));
        verify_ones_complement_ok(sum);
    }

    #[test]
    fn udp_checksum_odd_length_payload_property_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 7];

        let mut udp = [0u8; 13];
        udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        udp[2..4].copy_from_slice(&443u16.to_be_bytes());
        let udp_len = udp.len() as u16;
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp[12] = 0xcc;

        let checksum = udp_checksum_ipv6(&src, &dst, &udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());

        let sum = checksum16_with_seed_for_test(&udp, pseudo_sum_v6_udp(&src, &dst, udp.len()));
        verify_ones_complement_ok(sum);
    }

    #[test]
    fn udp_checksum_small_payload_property_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 1];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 2];

        let mut udp = [0u8; 40];
        udp[0..2].copy_from_slice(&54321u16.to_be_bytes());
        udp[2..4].copy_from_slice(&80u16.to_be_bytes());
        let udp_len = udp.len() as u16;
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        for i in 0..32 {
            udp[8 + i] = 255u8.wrapping_sub(i as u8);
        }

        let checksum = udp_checksum_ipv6(&src, &dst, &udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());

        let sum = checksum16_with_seed_for_test(&udp, pseudo_sum_v6_udp(&src, &dst, udp.len()));
        verify_ones_complement_ok(sum);
    }

    #[test]
    fn udp_checksum_short_slice_no_panic() {
        let src_v4 = u32::from_be_bytes([203, 0, 113, 10]);
        let dst_v4 = u32::from_be_bytes([198, 51, 100, 11]);
        let src_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4];
        let dst_v6 = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 8];

        for len in 0..8 {
            let udp = [0x5au8; 7];
            let value_v4 = udp_checksum_ipv4(src_v4, dst_v4, &udp[..len]);
            let value_v6 = udp_checksum_ipv6(&src_v6, &dst_v6, &udp[..len]);
            assert_ne!(value_v4, 0);
            assert_ne!(value_v6, 0);
        }
    }

    fn add_remove_words(mut sum: u32, old_bytes: &[u8], new_bytes: &[u8]) -> u32 {
        let mut old_chunks = old_bytes.chunks_exact(2);
        for chunk in &mut old_chunks {
            let old_word = u16::from_be_bytes([chunk[0], chunk[1]]);
            sum = sum.wrapping_add(u32::from(!old_word));
        }
        if let Some(&last) = old_chunks.remainder().first() {
            let old_word = u16::from_be_bytes([last, 0]);
            sum = sum.wrapping_add(u32::from(!old_word));
        }

        let mut new_chunks = new_bytes.chunks_exact(2);
        for chunk in &mut new_chunks {
            let new_word = u16::from_be_bytes([chunk[0], chunk[1]]);
            sum = sum.wrapping_add(u32::from(new_word));
        }
        if let Some(&last) = new_chunks.remainder().first() {
            let new_word = u16::from_be_bytes([last, 0]);
            sum = sum.wrapping_add(u32::from(new_word));
        }

        sum
    }

    fn nat64_incremental_tcp_checksum_v6_to_v4(
        initial_v6_checksum: u16,
        old_pseudo_v6: &[u8],
        new_pseudo_v4: &[u8],
        old_sport_be: u16,
        new_sport_be: u16,
    ) -> u16 {
        let mut sum = u32::from(!initial_v6_checksum);
        sum = add_remove_words(sum, old_pseudo_v6, new_pseudo_v4);
        sum = sum.wrapping_add(u32::from(!old_sport_be));
        sum = sum.wrapping_add(u32::from(new_sport_be));

        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        let out = !(sum as u16);
        if out == 0 { 0xffff } else { out }
    }

    #[test]
    fn nat64_tcp_v6_to_v4_incremental_matches_full_recompute() {
        let src_v6 = [
            0xfd, 0x00, 0x13, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
        ];
        let dst_v6 = [
            0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x15, 0x16, 0x63,
        ];
        let src_v4 = u32::from_be_bytes([192, 168, 1, 250]);
        let dst_v4 = u32::from_be_bytes([2, 21, 22, 99]);

        let old_sport = 45678u16;
        let new_sport = 40000u16;
        let dport = 443u16;

        let mut tcp = [0u8; 28];
        tcp[0..2].copy_from_slice(&old_sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
        tcp[12] = 7u8 << 4; // data offset 7 (28 bytes)
        tcp[13] = 0x02; // SYN
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
        tcp[16..18].copy_from_slice(&0u16.to_be_bytes());
        tcp[18..20].copy_from_slice(&0u16.to_be_bytes());
        tcp[20..22].copy_from_slice(&2u16.to_be_bytes());
        tcp[22..24].copy_from_slice(&4u16.to_be_bytes());
        tcp[24..26].copy_from_slice(&0x05b4u16.to_be_bytes());
        tcp[26..28].copy_from_slice(&0u16.to_be_bytes());

        let initial_v6_checksum = tcp_checksum_ipv6(&src_v6, &dst_v6, &tcp);
        let mut tcp_v6 = tcp;
        tcp_v6[16..18].copy_from_slice(&initial_v6_checksum.to_be_bytes());

        // final packet bytes after NAT64 v6->v4 forward rewrite
        let mut tcp_v4 = tcp_v6;
        tcp_v4[0..2].copy_from_slice(&new_sport.to_be_bytes());
        tcp_v4[16..18].copy_from_slice(&0u16.to_be_bytes());
        let expected_v4_checksum = tcp_checksum_ipv4(src_v4, dst_v4, &tcp_v4);

        // emulate the same incremental update mathematically: pseudo-header replacement + source-port rewrite
        let mut old_pseudo = [0u8; 40];
        old_pseudo[0..16].copy_from_slice(&src_v6);
        old_pseudo[16..32].copy_from_slice(&dst_v6);
        old_pseudo[32..36].copy_from_slice(&(tcp.len() as u32).to_be_bytes());
        old_pseudo[39] = 6;

        let mut new_pseudo = [0u8; 12];
        new_pseudo[0..4].copy_from_slice(&src_v4.to_be_bytes());
        new_pseudo[4..8].copy_from_slice(&dst_v4.to_be_bytes());
        new_pseudo[9] = 6;
        new_pseudo[10..12].copy_from_slice(&(tcp.len() as u16).to_be_bytes());

        let updated = nat64_incremental_tcp_checksum_v6_to_v4(
            initial_v6_checksum,
            &old_pseudo,
            &new_pseudo,
            old_sport,
            new_sport,
        );

        assert_eq!(updated, expected_v4_checksum);
    }
    #[test]
    fn nat64_tcp_v6_to_v4_incremental_matches_full_recompute_real_syn_options_vector() {
        let src_v6 = [
            0xfd, 0x00, 0x13, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
        ];
        let dst_v6 = [
            0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x15, 0x16, 0x81,
        ];
        let src_v4 = u32::from_be_bytes([192, 168, 1, 250]);
        let dst_v4 = u32::from_be_bytes([2, 21, 22, 129]);

        let old_sport = 44104u16;
        let new_sport = 40000u16;
        let dport = 443u16;

        // TCP SYN with MSS/SACK/TS/WS options (40-byte header, no payload).
        let mut tcp = [0u8; 40];
        tcp[0..2].copy_from_slice(&old_sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x2f35_a631u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
        tcp[12] = 10u8 << 4; // data offset 10 => 40 bytes
        tcp[13] = 0x02; // SYN
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
        tcp[16..18].copy_from_slice(&0u16.to_be_bytes());
        tcp[18..20].copy_from_slice(&0u16.to_be_bytes());
        // options: MSS(1460), SACK permitted, TS, NOP, WS(7)
        tcp[20..24].copy_from_slice(&[0x02, 0x04, 0x05, 0xb4]);
        tcp[24..28].copy_from_slice(&[0x04, 0x02, 0x08, 0x0a]);
        tcp[28..32].copy_from_slice(&0x01f7_3d1au32.to_be_bytes());
        tcp[32..36].copy_from_slice(&0u32.to_be_bytes());
        tcp[36..40].copy_from_slice(&[0x01, 0x03, 0x03, 0x07]);

        let initial_v6_checksum = tcp_checksum_ipv6(&src_v6, &dst_v6, &tcp);

        let mut tcp_v4 = tcp;
        tcp_v4[0..2].copy_from_slice(&new_sport.to_be_bytes());
        tcp_v4[16..18].copy_from_slice(&0u16.to_be_bytes());
        let expected_v4_checksum = tcp_checksum_ipv4(src_v4, dst_v4, &tcp_v4);

        let mut old_pseudo = [0u8; 40];
        old_pseudo[0..16].copy_from_slice(&src_v6);
        old_pseudo[16..32].copy_from_slice(&dst_v6);
        old_pseudo[32..36].copy_from_slice(&(tcp.len() as u32).to_be_bytes());
        old_pseudo[39] = 6;

        let mut new_pseudo = [0u8; 12];
        new_pseudo[0..4].copy_from_slice(&src_v4.to_be_bytes());
        new_pseudo[4..8].copy_from_slice(&dst_v4.to_be_bytes());
        new_pseudo[9] = 6;
        new_pseudo[10..12].copy_from_slice(&(tcp.len() as u16).to_be_bytes());

        let updated = nat64_incremental_tcp_checksum_v6_to_v4(
            initial_v6_checksum,
            &old_pseudo,
            &new_pseudo,
            old_sport,
            new_sport,
        );

        assert_eq!(updated, expected_v4_checksum);
    }
}
