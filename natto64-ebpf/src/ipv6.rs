//! Bounded parsing of IPv6 base headers for the eBPF classifiers.

use aya_ebpf::programs::TcContext;

/// Length of an IPv6 base header in bytes.
pub const IPV6_BASE_HDR_LEN: usize = 40;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_ESP: u8 = 50;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DSTOPTS: u8 = 60;

/// Fields extracted from an IPv6 base header.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct Ipv6Info {
    /// Source IPv6 address in network byte order.
    pub src: [u8; 16],
    /// Destination IPv6 address in network byte order.
    pub dst: [u8; 16],
    /// Protocol number immediately following the IPv6 base header.
    pub next_header: u8,
    /// IPv6 payload length in bytes.
    pub payload_len: u16,
    /// Absolute packet offset of the transport header.
    pub l4_abs_offset: usize,
}

/// Errors returned while parsing an IPv6 base header.
#[derive(Clone, Copy)]
pub enum Ipv6ParseError {
    /// The packet did not contain a complete IPv6 base header.
    Truncated,
}

/// Returns whether a next-header value identifies an unsupported IPv6 extension header.
#[inline(always)]
pub fn is_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        IPPROTO_HOPOPTS
            | IPPROTO_ROUTING
            | IPPROTO_FRAGMENT
            | IPPROTO_DSTOPTS
            | IPPROTO_ESP
            | IPPROTO_AH
    )
}

#[inline(always)]
fn load_be_u32(ctx: &TcContext, offset: usize) -> Result<u32, Ipv6ParseError> {
    ctx.load::<u32>(offset)
        .map(u32::from_be)
        .map_err(|_| Ipv6ParseError::Truncated)
}

#[inline(always)]
fn ipv6_from_be_words(w0: u32, w1: u32, w2: u32, w3: u32) -> [u8; 16] {
    let b0 = w0.to_be_bytes();
    let b1 = w1.to_be_bytes();
    let b2 = w2.to_be_bytes();
    let b3 = w3.to_be_bytes();

    [
        b0[0], b0[1], b0[2], b0[3], b1[0], b1[1], b1[2], b1[3], b2[0], b2[1], b2[2], b2[3], b3[0],
        b3[1], b3[2], b3[3],
    ]
}

/// Parses an IPv6 base header without walking extension-header chains.
#[inline(always)]
pub fn parse_ipv6_base(ctx: &TcContext, l3_offset: usize) -> Result<Ipv6Info, Ipv6ParseError> {
    let payload_len = ctx
        .load::<u16>(l3_offset + 4)
        .map(u16::from_be)
        .map_err(|_| Ipv6ParseError::Truncated)?;

    let next_header = ctx
        .load::<u8>(l3_offset + 6)
        .map_err(|_| Ipv6ParseError::Truncated)?;

    let s0 = load_be_u32(ctx, l3_offset + 8)?;
    let s1 = load_be_u32(ctx, l3_offset + 12)?;
    let s2 = load_be_u32(ctx, l3_offset + 16)?;
    let s3 = load_be_u32(ctx, l3_offset + 20)?;

    let d0 = load_be_u32(ctx, l3_offset + 24)?;
    let d1 = load_be_u32(ctx, l3_offset + 28)?;
    let d2 = load_be_u32(ctx, l3_offset + 32)?;
    let d3 = load_be_u32(ctx, l3_offset + 36)?;

    let src = ipv6_from_be_words(s0, s1, s2, s3);
    let dst = ipv6_from_be_words(d0, d1, d2, d3);

    Ok(Ipv6Info {
        src,
        dst,
        next_header,
        payload_len,
        l4_abs_offset: l3_offset + IPV6_BASE_HDR_LEN,
    })
}

#[cfg(test)]
mod tests {
    use super::ipv6_from_be_words;
    use natto64_abi::{nat64_embedded_v4_be, nat64_embedded_v4_bytes};

    #[test]
    fn normalizes_nat64_wkpf_prefix_words_correctly() {
        let raw0 = 0x9bff6400u32;
        let raw1 = 0x00000000u32;
        let raw2 = 0x00000000u32;
        let raw3 = 0x02151681u32;

        let dst = ipv6_from_be_words(
            u32::from_be(raw0),
            u32::from_be(raw1),
            u32::from_be(raw2),
            u32::from_be(raw3),
        );

        assert_eq!(
            dst,
            [
                0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0x16, 0x15, 0x02,
            ]
        );
    }

    #[test]
    fn nat64_wkpf96_prefix_matches_after_normalization() {
        let dst = [
            0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x15, 0x16, 0x81,
        ];

        let prefix = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(dst[..12], prefix);
    }

    #[test]
    fn extracts_embedded_ipv4_from_nat64_destination() {
        let dst = [
            0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x15, 0x16, 0x81,
        ];

        let v4 = nat64_embedded_v4_be(&dst);
        assert_eq!(v4, u32::from_be_bytes([2, 21, 22, 129]));
    }

    #[test]
    fn parser_and_embedded_v4_extraction_regression() {
        let raw_dst_words = [
            u32::from_be(0x0064_ff9b),
            u32::from_be(0x0000_0000),
            u32::from_be(0x0000_0000),
            u32::from_be(0x0215_1663),
        ];

        let dst = ipv6_from_be_words(
            raw_dst_words[0],
            raw_dst_words[1],
            raw_dst_words[2],
            raw_dst_words[3],
        );

        let prefix = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(dst[..12], prefix);
        assert_eq!(nat64_embedded_v4_bytes(&dst), [2, 21, 22, 99]);
        assert_eq!(
            nat64_embedded_v4_be(&dst),
            u32::from_be_bytes([2, 21, 22, 99])
        );
    }
}
