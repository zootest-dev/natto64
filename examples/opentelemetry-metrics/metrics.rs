use natto64::Nat64Metrics;

pub struct MetricDescriptor {
    pub name: &'static str,
    pub description: &'static str,
    pub value: fn(&Nat64Metrics) -> u64,
}

pub const DESCRIPTORS: &[MetricDescriptor] = &[
    MetricDescriptor {
        name: "nat64.pkts_total",
        description: "Packets that entered either NAT64 classifier.",
        value: |m| m.pkts_total,
    },
    MetricDescriptor {
        name: "nat64.pkts_ipv6",
        description: "IPv6 packets observed by the forward classifier.",
        value: |m| m.pkts_ipv6,
    },
    MetricDescriptor {
        name: "nat64.pkts_ipv4",
        description: "IPv4 packets observed by the reverse classifier.",
        value: |m| m.pkts_ipv4,
    },
    MetricDescriptor {
        name: "nat64.pkts_nat64_dst",
        description: "IPv6 packets whose destination matched the configured NAT64 prefix.",
        value: |m| m.pkts_nat64_dst,
    },
    MetricDescriptor {
        name: "nat64.pkts_nat64_tcp",
        description: "Prefix-matching forward packets carrying TCP.",
        value: |m| m.pkts_nat64_tcp,
    },
    MetricDescriptor {
        name: "nat64.pkts_nat64_udp",
        description: "Prefix-matching forward packets carrying UDP.",
        value: |m| m.pkts_nat64_udp,
    },
    MetricDescriptor {
        name: "nat64.pkts_ipv4_tcp",
        description: "Reverse-path IPv4 packets carrying TCP.",
        value: |m| m.pkts_ipv4_tcp,
    },
    MetricDescriptor {
        name: "nat64.pkts_ipv4_udp",
        description: "Reverse-path IPv4 packets carrying UDP.",
        value: |m| m.pkts_ipv4_udp,
    },
    MetricDescriptor {
        name: "nat64.nat64_v6_to_v4_ok",
        description: "Successful forward TCP translations.",
        value: |m| m.nat64_v6_to_v4_ok,
    },
    MetricDescriptor {
        name: "nat64.nat64_v6_to_v4_udp_ok",
        description: "Successful forward UDP translations.",
        value: |m| m.nat64_v6_to_v4_udp_ok,
    },
    MetricDescriptor {
        name: "nat64.nat64_v6_to_v4_err_write_hdr",
        description: "Forward translations that failed while writing an IPv4 header.",
        value: |m| m.nat64_v6_to_v4_err_write_hdr,
    },
    MetricDescriptor {
        name: "nat64.nat64_v6_to_v4_err_csum",
        description: "Forward translations that failed while updating a transport checksum.",
        value: |m| m.nat64_v6_to_v4_err_csum,
    },
    MetricDescriptor {
        name: "nat64.nat64_v4_to_v6_ok",
        description: "Successful reverse TCP translations.",
        value: |m| m.nat64_v4_to_v6_ok,
    },
    MetricDescriptor {
        name: "nat64.nat64_v4_to_v6_udp_ok",
        description: "Successful reverse UDP translations.",
        value: |m| m.nat64_v4_to_v6_udp_ok,
    },
    MetricDescriptor {
        name: "nat64.nat64_v4_to_v6_err_write_hdr",
        description: "Reverse translations that failed while writing an IPv6 header.",
        value: |m| m.nat64_v4_to_v6_err_write_hdr,
    },
    MetricDescriptor {
        name: "nat64.nat64_v4_to_v6_err_csum",
        description: "Reverse translations that failed while updating a transport checksum.",
        value: |m| m.nat64_v4_to_v6_err_csum,
    },
    MetricDescriptor {
        name: "nat64.nat64_v4_to_v6_udp_miss",
        description: "Reverse UDP packets with no matching NAT entry.",
        value: |m| m.nat64_v4_to_v6_udp_miss,
    },
    MetricDescriptor {
        name: "nat64.nat64_v4_to_v6_udp_tuple_mismatch",
        description: "Reverse UDP packets whose remote tuple did not match the NAT entry.",
        value: |m| m.nat64_v4_to_v6_udp_tuple_mismatch,
    },
    MetricDescriptor {
        name: "nat64.nat_lookup_hit",
        description: "Successful reverse NAT lookups.",
        value: |m| m.nat_lookup_hit,
    },
    MetricDescriptor {
        name: "nat64.nat_lookup_miss",
        description: "Reverse NAT lookups that did not produce a usable entry.",
        value: |m| m.nat_lookup_miss,
    },
    MetricDescriptor {
        name: "nat64.nat_lookup_tuple_mismatch",
        description: "Reverse TCP lookups rejected because the remote tuple differed.",
        value: |m| m.nat_lookup_tuple_mismatch,
    },
    MetricDescriptor {
        name: "nat64.nat_hit_refresh_ok",
        description: "NAT entries successfully refreshed after a reverse-path hit.",
        value: |m| m.nat_hit_refresh_ok,
    },
    MetricDescriptor {
        name: "nat64.nat_hit_refresh_err",
        description: "NAT entries that could not be refreshed after a reverse-path hit.",
        value: |m| m.nat_hit_refresh_err,
    },
    MetricDescriptor {
        name: "nat64.fwd_nat_lookup_hit",
        description: "Forward flows that reused an existing mapping.",
        value: |m| m.fwd_nat_lookup_hit,
    },
    MetricDescriptor {
        name: "nat64.fwd_nat_lookup_miss",
        description: "Forward flows that required a new mapping.",
        value: |m| m.fwd_nat_lookup_miss,
    },
    MetricDescriptor {
        name: "nat64.fwd_nat_insert_ok",
        description: "Forward-flow mappings inserted successfully.",
        value: |m| m.fwd_nat_insert_ok,
    },
    MetricDescriptor {
        name: "nat64.fwd_nat_insert_err",
        description: "Forward-flow mappings that could not be inserted.",
        value: |m| m.fwd_nat_insert_err,
    },
    MetricDescriptor {
        name: "nat64.fwd_nat_refresh_ok",
        description: "Forward-flow mappings refreshed successfully.",
        value: |m| m.fwd_nat_refresh_ok,
    },
    MetricDescriptor {
        name: "nat64.fwd_nat_refresh_err",
        description: "Forward-flow mappings that could not be refreshed.",
        value: |m| m.fwd_nat_refresh_err,
    },
    MetricDescriptor {
        name: "nat64.port_alloc_ok",
        description: "External port allocations that succeeded.",
        value: |m| m.port_alloc_ok,
    },
    MetricDescriptor {
        name: "nat64.port_alloc_err",
        description: "External port allocations that failed.",
        value: |m| m.port_alloc_err,
    },
    MetricDescriptor {
        name: "nat64.port_alloc_exhausted",
        description: "Allocation attempts that exhausted the configured port range.",
        value: |m| m.port_alloc_exhausted,
    },
    MetricDescriptor {
        name: "nat64.unsupported_ipv6_extension_headers",
        description: "NAT64-prefix IPv6 packets carrying an unsupported extension header.",
        value: |m| m.unsupported_ipv6_extension_headers,
    },
    MetricDescriptor {
        name: "nat64.unsupported_ipv6_non_tcp_udp",
        description: "NAT64-prefix IPv6 packets carrying a protocol other than TCP or UDP.",
        value: |m| m.unsupported_ipv6_non_tcp_udp,
    },
    MetricDescriptor {
        name: "nat64.unsupported_ipv4_fragments",
        description: "IPv4 fragments addressed to the configured external IPv4 pool.",
        value: |m| m.unsupported_ipv4_fragments,
    },
    MetricDescriptor {
        name: "nat64.unsupported_ipv4_non_tcp_udp",
        description: "Pool-addressed IPv4 packets carrying a protocol other than TCP or UDP.",
        value: |m| m.unsupported_ipv4_non_tcp_udp,
    },
    MetricDescriptor {
        name: "nat64.unsupported_ipv4_udp_zero_checksum",
        description: "Reverse IPv4 UDP packets with a zero checksum.",
        value: |m| m.unsupported_ipv4_udp_zero_checksum,
    },
    MetricDescriptor {
        name: "nat64.fwd_redirect_ok",
        description: "Forward translations successfully redirected to the uplink.",
        value: |m| m.fwd_redirect_ok,
    },
    MetricDescriptor {
        name: "nat64.fwd_redirect_err",
        description: "Forward redirects that failed or returned a non-redirect action.",
        value: |m| m.fwd_redirect_err,
    },
    MetricDescriptor {
        name: "nat64.rev_redirect_ok",
        description: "Reverse translations successfully redirected to the bridge.",
        value: |m| m.rev_redirect_ok,
    },
    MetricDescriptor {
        name: "nat64.rev_redirect_err",
        description: "Reverse redirects that failed or returned a non-redirect action.",
        value: |m| m.rev_redirect_err,
    },
];
