//! Production metrics snapshots exposed by the NAT64 userspace API.

use natto64_abi::ProdCounters;

/// Aggregated, process-wide snapshot of cumulative production counters.
///
/// Values are summed across all possible CPUs from the dataplane's production
/// per-CPU counter array. The snapshot is cumulative and reading it does not
/// reset dataplane counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Nat64Metrics {
    /// Packets that entered either NAT64 classifier.
    pub pkts_total: u64,
    /// IPv6 packets observed by the forward classifier.
    pub pkts_ipv6: u64,
    /// IPv4 packets observed by the reverse classifier.
    pub pkts_ipv4: u64,
    /// IPv6 packets whose destination matched the configured NAT64 prefix.
    pub pkts_nat64_dst: u64,
    /// Prefix-matching forward packets carrying TCP.
    pub pkts_nat64_tcp: u64,
    /// Prefix-matching forward packets carrying UDP.
    pub pkts_nat64_udp: u64,
    /// Reverse-path IPv4 packets carrying TCP.
    pub pkts_ipv4_tcp: u64,
    /// Reverse-path IPv4 packets carrying UDP.
    pub pkts_ipv4_udp: u64,
    /// Successful forward TCP translations.
    pub nat64_v6_to_v4_ok: u64,
    /// Successful forward UDP translations.
    pub nat64_v6_to_v4_udp_ok: u64,
    /// Forward translations that failed while writing an IPv4 header.
    pub nat64_v6_to_v4_err_write_hdr: u64,
    /// Forward translations that failed while updating a transport checksum.
    pub nat64_v6_to_v4_err_csum: u64,
    /// Successful reverse TCP translations.
    pub nat64_v4_to_v6_ok: u64,
    /// Successful reverse UDP translations.
    pub nat64_v4_to_v6_udp_ok: u64,
    /// Reverse translations that failed while writing an IPv6 header.
    pub nat64_v4_to_v6_err_write_hdr: u64,
    /// Reverse translations that failed while updating a transport checksum.
    pub nat64_v4_to_v6_err_csum: u64,
    /// Reverse UDP packets with no matching NAT entry.
    pub nat64_v4_to_v6_udp_miss: u64,
    /// Reverse UDP packets whose remote tuple did not match the NAT entry.
    pub nat64_v4_to_v6_udp_tuple_mismatch: u64,
    /// Successful reverse NAT lookups.
    pub nat_lookup_hit: u64,
    /// Reverse NAT lookups that did not produce a usable entry.
    pub nat_lookup_miss: u64,
    /// Reverse TCP lookups rejected because the remote tuple differed.
    pub nat_lookup_tuple_mismatch: u64,
    /// NAT entries successfully refreshed after a reverse-path hit.
    pub nat_hit_refresh_ok: u64,
    /// NAT entries that could not be refreshed after a reverse-path hit.
    pub nat_hit_refresh_err: u64,
    /// Forward flows that reused an existing mapping.
    pub fwd_nat_lookup_hit: u64,
    /// Forward flows that required a new mapping.
    pub fwd_nat_lookup_miss: u64,
    /// Forward-flow mappings inserted successfully.
    pub fwd_nat_insert_ok: u64,
    /// Forward-flow mappings that could not be inserted.
    pub fwd_nat_insert_err: u64,
    /// Forward-flow mappings refreshed successfully.
    pub fwd_nat_refresh_ok: u64,
    /// Forward-flow mappings that could not be refreshed.
    pub fwd_nat_refresh_err: u64,
    /// External port allocations that succeeded.
    pub port_alloc_ok: u64,
    /// External port allocations that failed.
    pub port_alloc_err: u64,
    /// Allocation attempts that exhausted the configured port range.
    pub port_alloc_exhausted: u64,
    /// NAT64-prefix IPv6 packets carrying an unsupported extension header.
    pub unsupported_ipv6_extension_headers: u64,
    /// NAT64-prefix IPv6 packets carrying a protocol other than TCP or UDP.
    pub unsupported_ipv6_non_tcp_udp: u64,
    /// IPv4 fragments addressed to the configured external IPv4 pool.
    pub unsupported_ipv4_fragments: u64,
    /// Pool-addressed IPv4 packets carrying a protocol other than TCP or UDP.
    pub unsupported_ipv4_non_tcp_udp: u64,
    /// Reverse IPv4 UDP packets with matching NAT state that cannot be translated because
    /// their checksum is zero.
    pub unsupported_ipv4_udp_zero_checksum: u64,
    /// Forward translations successfully redirected to the uplink.
    pub fwd_redirect_ok: u64,
    /// Forward redirects that failed or returned a non-redirect action.
    pub fwd_redirect_err: u64,
    /// Reverse translations successfully redirected to the bridge.
    pub rev_redirect_ok: u64,
    /// Reverse redirects that failed or returned a non-redirect action.
    pub rev_redirect_err: u64,
}

pub(crate) fn aggregate_prod_counters<'a>(
    values: impl IntoIterator<Item = &'a ProdCounters>,
) -> Nat64Metrics {
    let mut metrics = Nat64Metrics::default();
    for value in values {
        metrics.pkts_total = metrics.pkts_total.saturating_add(value.pkts_total);
        metrics.pkts_ipv6 = metrics.pkts_ipv6.saturating_add(value.pkts_ipv6);
        metrics.pkts_ipv4 = metrics.pkts_ipv4.saturating_add(value.pkts_ipv4);
        metrics.pkts_nat64_dst = metrics.pkts_nat64_dst.saturating_add(value.pkts_nat64_dst);
        metrics.pkts_nat64_tcp = metrics.pkts_nat64_tcp.saturating_add(value.pkts_nat64_tcp);
        metrics.pkts_nat64_udp = metrics.pkts_nat64_udp.saturating_add(value.pkts_nat64_udp);
        metrics.pkts_ipv4_tcp = metrics.pkts_ipv4_tcp.saturating_add(value.pkts_ipv4_tcp);
        metrics.pkts_ipv4_udp = metrics.pkts_ipv4_udp.saturating_add(value.pkts_ipv4_udp);
        metrics.nat64_v6_to_v4_ok = metrics
            .nat64_v6_to_v4_ok
            .saturating_add(value.nat64_v6_to_v4_ok);
        metrics.nat64_v6_to_v4_udp_ok = metrics
            .nat64_v6_to_v4_udp_ok
            .saturating_add(value.nat64_v6_to_v4_udp_ok);
        metrics.nat64_v6_to_v4_err_write_hdr = metrics
            .nat64_v6_to_v4_err_write_hdr
            .saturating_add(value.nat64_v6_to_v4_err_write_hdr);
        metrics.nat64_v6_to_v4_err_csum = metrics
            .nat64_v6_to_v4_err_csum
            .saturating_add(value.nat64_v6_to_v4_err_csum);
        metrics.nat64_v4_to_v6_ok = metrics
            .nat64_v4_to_v6_ok
            .saturating_add(value.nat64_v4_to_v6_ok);
        metrics.nat64_v4_to_v6_udp_ok = metrics
            .nat64_v4_to_v6_udp_ok
            .saturating_add(value.nat64_v4_to_v6_udp_ok);
        metrics.nat64_v4_to_v6_err_write_hdr = metrics
            .nat64_v4_to_v6_err_write_hdr
            .saturating_add(value.nat64_v4_to_v6_err_write_hdr);
        metrics.nat64_v4_to_v6_err_csum = metrics
            .nat64_v4_to_v6_err_csum
            .saturating_add(value.nat64_v4_to_v6_err_csum);
        metrics.nat64_v4_to_v6_udp_miss = metrics
            .nat64_v4_to_v6_udp_miss
            .saturating_add(value.nat64_v4_to_v6_udp_miss);
        metrics.nat64_v4_to_v6_udp_tuple_mismatch = metrics
            .nat64_v4_to_v6_udp_tuple_mismatch
            .saturating_add(value.nat64_v4_to_v6_udp_tuple_mismatch);
        metrics.nat_lookup_hit = metrics.nat_lookup_hit.saturating_add(value.nat_lookup_hit);
        metrics.nat_lookup_miss = metrics
            .nat_lookup_miss
            .saturating_add(value.nat_lookup_miss);
        metrics.nat_lookup_tuple_mismatch = metrics
            .nat_lookup_tuple_mismatch
            .saturating_add(value.nat_lookup_tuple_mismatch);
        metrics.nat_hit_refresh_ok = metrics
            .nat_hit_refresh_ok
            .saturating_add(value.nat_hit_refresh_ok);
        metrics.nat_hit_refresh_err = metrics
            .nat_hit_refresh_err
            .saturating_add(value.nat_hit_refresh_err);
        metrics.fwd_nat_lookup_hit = metrics
            .fwd_nat_lookup_hit
            .saturating_add(value.fwd_nat_lookup_hit);
        metrics.fwd_nat_lookup_miss = metrics
            .fwd_nat_lookup_miss
            .saturating_add(value.fwd_nat_lookup_miss);
        metrics.fwd_nat_insert_ok = metrics
            .fwd_nat_insert_ok
            .saturating_add(value.fwd_nat_insert_ok);
        metrics.fwd_nat_insert_err = metrics
            .fwd_nat_insert_err
            .saturating_add(value.fwd_nat_insert_err);
        metrics.fwd_nat_refresh_ok = metrics
            .fwd_nat_refresh_ok
            .saturating_add(value.fwd_nat_refresh_ok);
        metrics.fwd_nat_refresh_err = metrics
            .fwd_nat_refresh_err
            .saturating_add(value.fwd_nat_refresh_err);
        metrics.port_alloc_ok = metrics.port_alloc_ok.saturating_add(value.port_alloc_ok);
        metrics.port_alloc_err = metrics.port_alloc_err.saturating_add(value.port_alloc_err);
        metrics.port_alloc_exhausted = metrics
            .port_alloc_exhausted
            .saturating_add(value.port_alloc_exhausted);
        metrics.unsupported_ipv6_extension_headers = metrics
            .unsupported_ipv6_extension_headers
            .saturating_add(value.unsupported_ipv6_extension_headers);
        metrics.unsupported_ipv6_non_tcp_udp = metrics
            .unsupported_ipv6_non_tcp_udp
            .saturating_add(value.unsupported_ipv6_non_tcp_udp);
        metrics.unsupported_ipv4_fragments = metrics
            .unsupported_ipv4_fragments
            .saturating_add(value.unsupported_ipv4_fragments);
        metrics.unsupported_ipv4_non_tcp_udp = metrics
            .unsupported_ipv4_non_tcp_udp
            .saturating_add(value.unsupported_ipv4_non_tcp_udp);
        metrics.unsupported_ipv4_udp_zero_checksum = metrics
            .unsupported_ipv4_udp_zero_checksum
            .saturating_add(value.unsupported_ipv4_udp_zero_checksum);
        metrics.fwd_redirect_ok = metrics
            .fwd_redirect_ok
            .saturating_add(value.fwd_redirect_ok);
        metrics.fwd_redirect_err = metrics
            .fwd_redirect_err
            .saturating_add(value.fwd_redirect_err);
        metrics.rev_redirect_ok = metrics
            .rev_redirect_ok
            .saturating_add(value.rev_redirect_ok);
        metrics.rev_redirect_err = metrics
            .rev_redirect_err
            .saturating_add(value.rev_redirect_err);
    }
    metrics
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(base: u64) -> ProdCounters {
        ProdCounters {
            pkts_total: base,
            pkts_ipv6: base + 1,
            pkts_ipv4: base + 2,
            pkts_nat64_dst: base + 3,
            pkts_nat64_tcp: base + 4,
            pkts_nat64_udp: base + 5,
            pkts_ipv4_tcp: base + 6,
            pkts_ipv4_udp: base + 7,
            nat64_v6_to_v4_ok: base + 8,
            nat64_v6_to_v4_udp_ok: base + 9,
            nat64_v6_to_v4_err_write_hdr: base + 10,
            nat64_v6_to_v4_err_csum: base + 11,
            nat64_v4_to_v6_ok: base + 12,
            nat64_v4_to_v6_udp_ok: base + 13,
            nat64_v4_to_v6_err_write_hdr: base + 14,
            nat64_v4_to_v6_err_csum: base + 15,
            nat64_v4_to_v6_udp_miss: base + 16,
            nat64_v4_to_v6_udp_tuple_mismatch: base + 17,
            nat_lookup_hit: base + 18,
            nat_lookup_miss: base + 19,
            nat_lookup_tuple_mismatch: base + 20,
            nat_hit_refresh_ok: base + 21,
            nat_hit_refresh_err: base + 22,
            fwd_nat_lookup_hit: base + 23,
            fwd_nat_lookup_miss: base + 24,
            fwd_nat_insert_ok: base + 25,
            fwd_nat_insert_err: base + 26,
            fwd_nat_refresh_ok: base + 27,
            fwd_nat_refresh_err: base + 28,
            port_alloc_ok: base + 29,
            port_alloc_err: base + 30,
            port_alloc_exhausted: base + 31,
            unsupported_ipv6_extension_headers: base + 32,
            unsupported_ipv6_non_tcp_udp: base + 33,
            unsupported_ipv4_fragments: base + 34,
            unsupported_ipv4_non_tcp_udp: base + 35,
            unsupported_ipv4_udp_zero_checksum: base + 36,
            fwd_redirect_ok: base + 37,
            fwd_redirect_err: base + 38,
            rev_redirect_ok: base + 39,
            rev_redirect_err: base + 40,
        }
    }

    #[test]
    fn one_cpu_maps_all_fields() {
        let value = counters(1);
        assert_eq!(
            aggregate_prod_counters([&value]),
            Nat64Metrics {
                pkts_total: 1,
                pkts_ipv6: 2,
                pkts_ipv4: 3,
                pkts_nat64_dst: 4,
                pkts_nat64_tcp: 5,
                pkts_nat64_udp: 6,
                pkts_ipv4_tcp: 7,
                pkts_ipv4_udp: 8,
                nat64_v6_to_v4_ok: 9,
                nat64_v6_to_v4_udp_ok: 10,
                nat64_v6_to_v4_err_write_hdr: 11,
                nat64_v6_to_v4_err_csum: 12,
                nat64_v4_to_v6_ok: 13,
                nat64_v4_to_v6_udp_ok: 14,
                nat64_v4_to_v6_err_write_hdr: 15,
                nat64_v4_to_v6_err_csum: 16,
                nat64_v4_to_v6_udp_miss: 17,
                nat64_v4_to_v6_udp_tuple_mismatch: 18,
                nat_lookup_hit: 19,
                nat_lookup_miss: 20,
                nat_lookup_tuple_mismatch: 21,
                nat_hit_refresh_ok: 22,
                nat_hit_refresh_err: 23,
                fwd_nat_lookup_hit: 24,
                fwd_nat_lookup_miss: 25,
                fwd_nat_insert_ok: 26,
                fwd_nat_insert_err: 27,
                fwd_nat_refresh_ok: 28,
                fwd_nat_refresh_err: 29,
                port_alloc_ok: 30,
                port_alloc_err: 31,
                port_alloc_exhausted: 32,
                unsupported_ipv6_extension_headers: 33,
                unsupported_ipv6_non_tcp_udp: 34,
                unsupported_ipv4_fragments: 35,
                unsupported_ipv4_non_tcp_udp: 36,
                unsupported_ipv4_udp_zero_checksum: 37,
                fwd_redirect_ok: 38,
                fwd_redirect_err: 39,
                rev_redirect_ok: 40,
                rev_redirect_err: 41,
            }
        );
    }

    #[test]
    fn multiple_cpus_are_summed() {
        let a = counters(1);
        let b = counters(100);
        let metrics = aggregate_prod_counters([&a, &b]);
        assert_eq!(metrics.pkts_total, 101);
        assert_eq!(metrics.rev_redirect_err, 181);
    }

    #[test]
    fn zero_values_remain_zero() {
        let values = [ProdCounters::default(), ProdCounters::default()];
        assert_eq!(
            aggregate_prod_counters(values.iter()),
            Nat64Metrics::default()
        );
    }

    #[test]
    fn aggregation_saturates() {
        let values = [
            ProdCounters {
                unsupported_ipv6_extension_headers: u64::MAX,
                ..Default::default()
            },
            ProdCounters {
                unsupported_ipv6_extension_headers: 1,
                ..Default::default()
            },
        ];
        assert_eq!(
            aggregate_prod_counters(values.iter()).unsupported_ipv6_extension_headers,
            u64::MAX
        );
    }
}
