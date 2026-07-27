//! Fixed-size IPv4 and IPv6 header builders.

use crate::checksum::ipv4_header_checksum_20b;

/// Builds a checksum-complete 20-byte IPv4 header for a TCP packet.
pub fn build_ipv4_header_tcp(
    src: [u8; 4],
    dst: [u8; 4],
    total_len: u16,
    ttl: u8,
    identification: u16,
) -> [u8; 20] {
    let mut hdr = [0u8; 20];
    hdr[0] = 0x45;
    hdr[1] = 0;
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    hdr[4..6].copy_from_slice(&identification.to_be_bytes());
    hdr[6..8].copy_from_slice(&0u16.to_be_bytes());
    hdr[8] = ttl;
    hdr[9] = 6;
    hdr[12..16].copy_from_slice(&src);
    hdr[16..20].copy_from_slice(&dst);

    let checksum = ipv4_header_checksum_20b(&hdr);
    hdr[10..12].copy_from_slice(&checksum.to_be_bytes());

    hdr
}

/// Builds a checksum-complete 20-byte IPv4 header for a UDP packet.
pub fn build_ipv4_header_udp(
    src: [u8; 4],
    dst: [u8; 4],
    total_len: u16,
    ttl: u8,
    identification: u16,
) -> [u8; 20] {
    let mut hdr = [0u8; 20];
    hdr[0] = 0x45;
    hdr[1] = 0;
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    hdr[4..6].copy_from_slice(&identification.to_be_bytes());
    hdr[6..8].copy_from_slice(&0u16.to_be_bytes());
    hdr[8] = ttl;
    hdr[9] = 17;
    hdr[12..16].copy_from_slice(&src);
    hdr[16..20].copy_from_slice(&dst);

    let checksum = ipv4_header_checksum_20b(&hdr);
    hdr[10..12].copy_from_slice(&checksum.to_be_bytes());

    hdr
}

/// Builds a 40-byte IPv6 base header for a TCP packet.
pub fn build_ipv6_header_tcp(
    src: [u8; 16],
    dst: [u8; 16],
    payload_len: u16,
    hop_limit: u8,
) -> [u8; 40] {
    let mut hdr = [0u8; 40];
    hdr[0] = 0x60;
    hdr[1] = 0;
    hdr[2] = 0;
    hdr[3] = 0;
    hdr[4..6].copy_from_slice(&payload_len.to_be_bytes());
    hdr[6] = 6;
    hdr[7] = hop_limit;
    hdr[8..24].copy_from_slice(&src);
    hdr[24..40].copy_from_slice(&dst);
    hdr
}

/// Builds a 40-byte IPv6 base header for a UDP packet.
pub fn build_ipv6_header_udp(
    src: [u8; 16],
    dst: [u8; 16],
    payload_len: u16,
    hop_limit: u8,
) -> [u8; 40] {
    let mut hdr = [0u8; 40];
    hdr[0] = 0x60;
    hdr[1] = 0;
    hdr[2] = 0;
    hdr[3] = 0;
    hdr[4..6].copy_from_slice(&payload_len.to_be_bytes());
    hdr[6] = 17;
    hdr[7] = hop_limit;
    hdr[8..24].copy_from_slice(&src);
    hdr[24..40].copy_from_slice(&dst);
    hdr
}

#[cfg(test)]
mod tests {
    use crate::checksum::checksum16;

    use super::{
        build_ipv4_header_tcp, build_ipv4_header_udp, build_ipv6_header_tcp, build_ipv6_header_udp,
    };

    fn parse_ipv4_header_20b(buf: &[u8; 20]) -> (u8, u8, u16, u8, u32, u32, bool) {
        let version = buf[0] >> 4;
        let ihl = buf[0] & 0x0f;
        let total_len = u16::from_be_bytes([buf[2], buf[3]]);
        let proto = buf[9];
        let src = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let dst = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let checksum_ok = checksum16(&buf[0..20]) == 0xFFFF;

        (version, ihl, total_len, proto, src, dst, checksum_ok)
    }

    fn parse_ipv6_header_40b(buf: &[u8; 40]) -> (u8, u16, u8, u8, [u8; 16], [u8; 16]) {
        let version = buf[0] >> 4;
        let payload_len = u16::from_be_bytes([buf[4], buf[5]]);
        let next_header = buf[6];
        let hop_limit = buf[7];
        let mut src = [0u8; 16];
        src.copy_from_slice(&buf[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&buf[24..40]);

        (version, payload_len, next_header, hop_limit, src, dst)
    }

    #[test]
    fn build_ipv4_header_tcp_sets_fields_and_checksum() {
        let src = [192, 0, 2, 1];
        let dst = [198, 51, 100, 2];
        let hdr = build_ipv4_header_tcp(src, dst, 40, 64, 0x1234);

        assert_eq!(hdr[0], 0x45);
        assert_eq!(hdr[1], 0);
        assert_eq!(&hdr[2..4], &40u16.to_be_bytes());
        assert_eq!(&hdr[4..6], &0x1234u16.to_be_bytes());
        assert_eq!(&hdr[6..8], &0u16.to_be_bytes());
        assert_eq!(hdr[8], 64);
        assert_eq!(hdr[9], 6);
        assert_eq!(&hdr[12..16], &src);
        assert_eq!(&hdr[16..20], &dst);
        assert_eq!(checksum16(&hdr), 0xFFFF);
    }

    #[test]
    fn build_ipv6_header_tcp_sets_fields() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 1];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 2];
        let hdr = build_ipv6_header_tcp(src, dst, 20, 55);

        assert_eq!(hdr[0], 0x60);
        assert_eq!(hdr[1], 0);
        assert_eq!(hdr[2], 0);
        assert_eq!(hdr[3], 0);
        assert_eq!(&hdr[4..6], &20u16.to_be_bytes());
        assert_eq!(hdr[6], 6);
        assert_eq!(hdr[7], 55);
        assert_eq!(&hdr[8..24], &src);
        assert_eq!(&hdr[24..40], &dst);
    }

    #[test]
    fn build_ipv4_header_udp_sets_fields_and_checksum() {
        let src = [192, 0, 2, 1];
        let dst = [198, 51, 100, 2];
        let hdr = build_ipv4_header_udp(src, dst, 40, 64, 0x1234);

        assert_eq!(hdr[0], 0x45);
        assert_eq!(hdr[1], 0);
        assert_eq!(&hdr[2..4], &40u16.to_be_bytes());
        assert_eq!(&hdr[4..6], &0x1234u16.to_be_bytes());
        assert_eq!(&hdr[6..8], &0u16.to_be_bytes());
        assert_eq!(hdr[8], 64);
        assert_eq!(hdr[9], 17);
        assert_eq!(&hdr[12..16], &src);
        assert_eq!(&hdr[16..20], &dst);
        assert_eq!(checksum16(&hdr), 0xFFFF);
    }

    #[test]
    fn build_ipv6_header_udp_sets_fields() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 1];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 2];
        let hdr = build_ipv6_header_udp(src, dst, 20, 55);

        assert_eq!(hdr[0], 0x60);
        assert_eq!(hdr[1], 0);
        assert_eq!(hdr[2], 0);
        assert_eq!(hdr[3], 0);
        assert_eq!(&hdr[4..6], &20u16.to_be_bytes());
        assert_eq!(hdr[6], 17);
        assert_eq!(hdr[7], 55);
        assert_eq!(&hdr[8..24], &src);
        assert_eq!(&hdr[24..40], &dst);
    }

    #[test]
    fn ipv4_header_builder_udp_parse_back() {
        let src = [192, 0, 2, 1];
        let dst = [198, 51, 100, 2];
        let total_len = 28;
        let hdr = build_ipv4_header_udp(src, dst, total_len, 64, 0x0102);

        let (version, ihl, parsed_total_len, proto, parsed_src, parsed_dst, checksum_ok) =
            parse_ipv4_header_20b(&hdr);
        assert_eq!(version, 4);
        assert_eq!(ihl, 5);
        assert_eq!(parsed_total_len, total_len);
        assert_eq!(proto, 17);
        assert_eq!(parsed_src, u32::from_be_bytes(src));
        assert_eq!(parsed_dst, u32::from_be_bytes(dst));
        assert!(checksum_ok);
    }

    #[test]
    fn ipv4_header_builder_tcp_parse_back() {
        let src = [10, 0, 0, 1];
        let dst = [8, 8, 8, 8];
        let total_len = 60;
        let hdr = build_ipv4_header_tcp(src, dst, total_len, 64, 0x0304);

        let (version, ihl, parsed_total_len, proto, parsed_src, parsed_dst, checksum_ok) =
            parse_ipv4_header_20b(&hdr);
        assert_eq!(version, 4);
        assert_eq!(ihl, 5);
        assert_eq!(parsed_total_len, total_len);
        assert_eq!(proto, 6);
        assert_eq!(parsed_src, u32::from_be_bytes(src));
        assert_eq!(parsed_dst, u32::from_be_bytes(dst));
        assert!(checksum_ok);
    }

    #[test]
    fn ipv6_header_builder_udp_parse_back() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 1];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 2];
        let payload_len = 1200;
        let hop_limit = 64;
        let hdr = build_ipv6_header_udp(src, dst, payload_len, hop_limit);

        let (version, parsed_payload_len, next_header, parsed_hop_limit, parsed_src, parsed_dst) =
            parse_ipv6_header_40b(&hdr);
        assert_eq!(version, 6);
        assert_eq!(parsed_payload_len, payload_len);
        assert_eq!(next_header, 17);
        assert_eq!(parsed_hop_limit, hop_limit);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn ipv6_header_builder_tcp_parse_back() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 1];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 2];
        let payload_len = 8;
        let hop_limit = 32;
        let hdr = build_ipv6_header_tcp(src, dst, payload_len, hop_limit);

        let (version, parsed_payload_len, next_header, parsed_hop_limit, parsed_src, parsed_dst) =
            parse_ipv6_header_40b(&hdr);
        assert_eq!(version, 6);
        assert_eq!(parsed_payload_len, payload_len);
        assert_eq!(next_header, 6);
        assert_eq!(parsed_hop_limit, hop_limit);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn header_length_boundary_sanity() {
        let ipv4 = build_ipv4_header_udp([192, 0, 2, 10], [198, 51, 100, 20], 20 + 8, 64, 0x1);
        let (_, _, total_len, _, _, _, checksum_ok) = parse_ipv4_header_20b(&ipv4);
        assert_eq!(total_len, 28);
        assert!(checksum_ok);

        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 1];
        let dst = [0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 2];

        for payload_len in [0u16, 8, 1200] {
            let ipv6 = build_ipv6_header_udp(src, dst, payload_len, 64);
            let (version, parsed_payload_len, next_header, hop_limit, parsed_src, parsed_dst) =
                parse_ipv6_header_40b(&ipv6);
            assert_eq!(version, 6);
            assert_eq!(parsed_payload_len, payload_len);
            assert_eq!(next_header, 17);
            assert_eq!(hop_limit, 64);
            assert_eq!(parsed_src, src);
            assert_eq!(parsed_dst, dst);
        }
    }
}
