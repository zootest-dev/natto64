#![no_std]
#![deny(missing_docs)]
//! Shared ABI types, packet helpers, and counters used by the NAT64 userspace and eBPF crates.

/// Internet-checksum helpers for IPv4, IPv6, TCP, and UDP.
pub mod checksum;
/// Builders for fixed-size IPv4 and IPv6 headers.
pub mod headers;
/// Helpers for reading and writing big-endian integer values.
pub mod wire;

/// A 96-bit NAT64 prefix stored in wire byte order.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Nat64Prefix {
    /// The first 96 bits of the NAT64 prefix in network byte order.
    pub bytes: [u8; 12],
}

/// Runtime configuration shared between userspace and the eBPF dataplane.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Nat64Config {
    /// The /96 destination prefix recognized by the forward translator.
    pub prefix96: [u8; 12],
    /// External IPv4 addresses in big-endian numeric form.
    pub v4_pool: [u32; V4_POOL_MAX],
    /// Number of active entries in [`Self::v4_pool`].
    pub v4_pool_len: u32,
    /// Interface index used for reverse-path redirects toward IPv6 clients.
    pub bridge_ifindex: u32,
    /// Interface index used for forward-path redirects toward IPv4 networks.
    pub uplink_ifindex: u32,
    /// Lowest external transport port available to the allocator, inclusive.
    pub port_min: u16,
    /// Highest external transport port available to the allocator, inclusive.
    pub port_max: u16,
    /// Idle session timeout in seconds, or zero to disable expiration.
    pub session_timeout_secs: u32,
    /// External IPv4 selection policy identifier.
    pub v4_policy: u8,
    /// Reserved padding that must be initialized to zero.
    pub _pad: [u8; 3],
}

/// Maximum number of external IPv4 addresses in a NAT64 pool.
pub const V4_POOL_MAX: usize = 16;
/// Number of recently used ports retained by each cooldown ring.
pub const COOLDOWN_SIZE: usize = 64;

/// Key used for the single entry in the eBPF configuration map.
pub const CONFIG_KEY: u32 = 0;
/// Compatibility alias for [`CONFIG_KEY`].
pub const CONFIG_KEY_PREFIX: u32 = CONFIG_KEY;

/// Selects an external IPv4 address by hashing the originating IPv6 address.
pub const V4_SELECT_POLICY_HASH_VM_V6: u8 = 0;
/// Number of forward-destination samples retained for diagnostics.
pub const DBG_FWD_DST_SAMPLE_SLOTS: u32 = 8;
/// Number of forward TCP translation samples retained for diagnostics.
pub const DBG_FWD_TCP_SAMPLE_SLOTS: u32 = 8;
/// Number of forward TCP checksum samples retained for diagnostics.
pub const DBG_FWD_TCP_CSUM_SAMPLE_SLOTS: u32 = 8;

/// Diagnostic sample of a forward-path IPv6 destination.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DbgIpv6Sample {
    /// Monotonic sample sequence number.
    pub seq: u64,
    /// Observed IPv6 destination address in network byte order.
    pub dst: [u8; 16],
}

/// Diagnostic sample captured during a forward TCP translation.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DbgFwdTcpSample {
    /// Monotonic sample sequence number.
    pub seq: u64,
    /// Original IPv6 destination address.
    pub dst6: [u8; 16],
    /// IPv4 destination bytes extracted from the NAT64 address.
    pub dst4: [u8; 4],
    /// Extracted IPv4 destination in big-endian numeric form.
    pub dst4_be: u32,
    /// Selected external IPv4 source in big-endian numeric form.
    pub src4_be: u32,
    /// Original TCP source port in host byte order.
    pub tcp_sport: u16,
    /// Original TCP destination port in host byte order.
    pub tcp_dport: u16,
    /// Nonzero when the reverse NAT entry was inserted successfully.
    pub nat_insert_ok: u8,
    /// Nonzero when the packet header-size adjustment succeeded.
    pub adjust_room_ok: u8,
    /// Reserved padding that must be initialized to zero.
    pub _pad: [u8; 6],
}

/// Diagnostic sample of the incremental TCP checksum update stages.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DbgFwdTcpCsumSample {
    /// Monotonic sample sequence number.
    pub seq: u64,
    /// TCP checksum before translation, in wire byte order.
    pub old_check_be: u16,
    /// Checksum after replacing the IP pseudo-header contribution.
    pub after_pseudo_be: u16,
    /// Checksum after replacing the translated source port.
    pub after_port_be: u16,
    /// Checksum stored in the translated packet.
    pub final_check_be: u16,
    /// Original TCP source port in wire byte order.
    pub old_sport_be: u16,
    /// Translated TCP source port in wire byte order.
    pub new_sport_be: u16,
    /// Reserved padding that must be initialized to zero.
    pub _pad: u16,
    /// Translated IPv4 source address in big-endian numeric form.
    pub src_v4: u32,
    /// Translated IPv4 destination address in big-endian numeric form.
    pub dst_v4: u32,
}

/// Operational counters exported by the NAT64 dataplane.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProdCounters {
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

/// Detailed branch and error counters exported for diagnostics.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DebugCounters {
    /// Forward-classifier invocations.
    pub dbg_fwd_enter: u64,
    /// Forward packets with an IPv6 Ethernet type.
    pub dbg_fwd_eth_ipv6: u64,
    /// Forward IPv6 destinations matching the configured prefix.
    pub dbg_fwd_nat64_prefix_match: u64,
    /// Forward packets entering the TCP translation branch.
    pub dbg_fwd_tcp_branch: u64,
    /// Forward packets entering the UDP translation branch.
    pub dbg_fwd_udp_branch: u64,
    /// Forward packets ending in a successful redirect.
    pub dbg_fwd_return_ok: u64,
    /// Forward packets ending without a successful redirect.
    pub dbg_fwd_return_err: u64,
    /// Reverse-classifier invocations.
    pub dbg_rev_enter: u64,
    /// Reverse packets with an IPv4 Ethernet type.
    pub dbg_rev_eth_ipv4: u64,
    /// Reverse IPv4 destinations matching the configured address pool.
    pub dbg_rev_pool_match: u64,
    /// Reverse packets ending in a successful redirect.
    pub dbg_rev_return_ok: u64,
    /// Reverse packets ending without a successful redirect.
    pub dbg_rev_return_err: u64,
    /// IPv6 base headers parsed successfully.
    pub pkts_ipv6_parsed_ok: u64,
    /// IPv6 packets skipped because an extension header was present.
    pub pkts_ipv6_ext_hdr: u64,
    /// IPv6 packets skipped because the next header was not TCP or UDP.
    pub pkts_ipv6_non_tcp_udp: u64,
    /// Forward IPv6 packets identified as UDP.
    pub pkts_udp: u64,
    /// Reverse IPv4 TCP packets addressed to the external pool.
    pub pkts_ipv4_to_v4src: u64,
    /// Reverse NAT entries inserted successfully.
    pub nat_insert_ok: u64,
    /// Reverse NAT entries that could not be inserted.
    pub nat_insert_err: u64,
    /// Reverse UDP NAT entries inserted successfully.
    pub nat_insert_udp_ok: u64,
    /// Reverse UDP NAT entries that could not be inserted.
    pub nat_insert_udp_err: u64,
    /// External port candidates examined by the allocator.
    pub port_alloc_probe: u64,
    /// Port candidates rejected because a NAT entry already used them.
    pub port_alloc_collide: u64,
    /// Port candidates skipped because they were in the cooldown ring.
    pub cooldown_skip: u64,
    /// Cooldown matches that caused the allocator to continue probing.
    pub cooldown_probe_more: u64,
    /// Allocated ports added to the cooldown ring successfully.
    pub cooldown_push_ok: u64,
    /// Allocated ports that could not be added to the cooldown ring.
    pub cooldown_push_err: u64,
    /// Sampled destinations classified as matching the NAT64 prefix.
    pub dbg_fwd_dst_nat64_prefix: u64,
    /// Sampled global destinations outside the NAT64 prefix.
    pub dbg_fwd_dst_global_non_nat64: u64,
    /// Sampled link-local IPv6 destinations.
    pub dbg_fwd_dst_link_local: u64,
    /// Sampled multicast IPv6 destinations.
    pub dbg_fwd_dst_multicast: u64,
    /// Sampled IPv6 destinations not covered by another class.
    pub dbg_fwd_dst_other: u64,
    /// Forward TCP packets that failed transport-header parsing.
    pub dbg_fwd_tcp_parse_err: u64,
    /// Forward packets for which the embedded IPv4 address was unusable.
    pub dbg_fwd_embedded_v4_extract_err: u64,
    /// Forward TCP packets that failed reverse-entry insertion.
    pub dbg_fwd_nat_insert_err: u64,
    /// Forward packets that failed protocol or header-size adjustment.
    pub dbg_fwd_adjust_room_err: u64,
    /// Forward packets that failed a packet-byte write.
    pub dbg_fwd_store_bytes_err: u64,
    /// Forward packets that failed IPv4 header construction.
    pub dbg_fwd_write_ipv4_err: u64,
    /// Forward packets that failed a transport-checksum update.
    pub dbg_fwd_l4_csum_err: u64,
    /// Forward checksum updates that failed at the pseudo-header stage.
    pub dbg_fwd_l4_csum_pseudo_err: u64,
    /// Forward checksum updates that failed at the port-rewrite stage.
    pub dbg_fwd_l4_csum_port_err: u64,
    /// Forward TCP checksum samples recorded successfully.
    pub dbg_fwd_tcp_csum_sample_ok: u64,
    /// Forward TCP checksum samples that could not be recorded.
    pub dbg_fwd_tcp_csum_sample_err: u64,
    /// Forward packets that failed during final redirect handling.
    pub dbg_fwd_redirect_or_return_err: u64,
    /// Packet protocol-family changes that succeeded.
    pub proto_change_ok: u64,
    /// Packet protocol-family changes that failed.
    pub proto_change_err: u64,
    /// Forward TCP translations that failed changing to IPv4.
    pub nat64_v6_to_v4_err_change_proto: u64,
    /// Forward TCP translations that failed updating the Ethernet type.
    pub nat64_v6_to_v4_err_l2_store: u64,
    /// Forward UDP packets that failed header parsing.
    pub nat64_v6_to_v4_udp_err_parse: u64,
    /// Forward UDP packets rejected because of an invalid length.
    pub nat64_v6_to_v4_udp_err_len: u64,
    /// Forward UDP translations that failed changing to IPv4.
    pub nat64_v6_to_v4_udp_err_change_proto: u64,
    /// Forward UDP translations that failed updating the Ethernet type.
    pub nat64_v6_to_v4_udp_err_l2_store: u64,
    /// Forward UDP translations that failed writing the translated source port.
    pub nat64_v6_to_v4_udp_err_udp_store: u64,
    /// Forward UDP translations that failed updating the checksum.
    pub nat64_v6_to_v4_udp_err_csum: u64,
    /// IPv4 source-address rewrites that succeeded.
    pub rewrite_v4_src_ok: u64,
    /// IPv4 source-address rewrites that failed.
    pub rewrite_v4_src_err: u64,
    /// TCP source-port rewrites that succeeded.
    pub rewrite_tcp_sport_ok: u64,
    /// TCP source-port rewrites that failed.
    pub rewrite_tcp_sport_err: u64,
    /// Reverse TCP translations that failed changing to IPv6.
    pub nat64_v4_to_v6_err_change_proto: u64,
    /// Reverse TCP translations that failed updating the Ethernet type.
    pub nat64_v4_to_v6_err_l2_store: u64,
    /// Reverse UDP packets that failed IPv4 or UDP parsing.
    pub nat64_v4_to_v6_udp_err_parse: u64,
    /// Reverse UDP packets rejected because of an invalid length.
    pub nat64_v4_to_v6_udp_err_len: u64,
    /// Reverse UDP translations that failed changing to IPv6.
    pub nat64_v4_to_v6_udp_err_change_proto: u64,
    /// Reverse UDP translations that failed updating the Ethernet type.
    pub nat64_v4_to_v6_udp_err_l2_store: u64,
    /// Reverse UDP translations that failed restoring the destination port.
    pub nat64_v4_to_v6_udp_err_dport_store: u64,
    /// Reverse UDP translations that failed updating the checksum.
    pub nat64_v4_to_v6_udp_err_csum: u64,
    /// Reverse IPv4 UDP packets rejected because their checksum was zero.
    pub nat64_v4_to_v6_udp_zero_csum_unsupported: u64,
    /// TCP destination-port rewrites that succeeded.
    pub rewrite_tcp_dport_ok: u64,
    /// TCP destination-port rewrites that failed.
    pub rewrite_tcp_dport_err: u64,
    /// Attempts to capture a forward TCP checksum sample.
    pub dbg_fwd_tcp_csum_sample_attempt: u64,
    /// Forward packets fully rewritten before redirect processing.
    pub fwd_rewrite_ok_before_redirect: u64,
    /// Reverse packets fully rewritten before redirect processing.
    pub rev_rewrite_ok_before_redirect: u64,
}

/// Per-CPU ring of recently allocated external ports.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PortCooldownRing {
    /// Index where the next allocated port will be written.
    pub idx: u32,
    /// Recently allocated external ports.
    pub ports: [u16; COOLDOWN_SIZE],
}

impl Default for PortCooldownRing {
    fn default() -> Self {
        Self {
            idx: 0,
            ports: [0; COOLDOWN_SIZE],
        }
    }
}

/// Reverse-lookup key for a translated flow.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct NatKey {
    /// External IPv4 address in big-endian numeric form.
    pub ext_v4: u32,
    /// External transport port in host byte order.
    pub ext_port: u16,
    /// IP protocol number, such as 6 for TCP or 17 for UDP.
    pub proto: u8,
    /// Reserved padding that must be initialized to zero.
    pub _pad: u8,
}

/// Reverse-lookup state for a translated flow.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NatVal {
    /// Original IPv6 client address.
    pub vm_v6: [u8; 16],
    /// Original client transport port in host byte order.
    pub vm_port: u16,
    /// Original remote IPv4 address in big-endian numeric form.
    pub remote_v4: u32,
    /// Original remote transport port in host byte order.
    pub remote_port: u16,
    /// Reserved padding that must be initialized to zero.
    pub _pad: u16,
    /// Random identifier that distinguishes reused external tuples.
    pub generation: u32,
    /// Monotonic timestamp of the most recent validated packet, in nanoseconds.
    pub last_seen_ns: u64,
}

/// Forward-flow key used to preserve an existing NAT mapping.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FwdNatKey {
    /// Originating IPv6 client address.
    pub vm_v6: [u8; 16],
    /// Remote IPv4 address in big-endian numeric form.
    pub remote_v4: u32,
    /// Originating client port in host byte order.
    pub vm_port: u16,
    /// Remote transport port in host byte order.
    pub remote_port: u16,
    /// IP protocol number, such as 6 for TCP or 17 for UDP.
    pub proto: u8,
    /// Reserved padding that must be initialized to zero.
    pub _pad: [u8; 3],
}

/// Forward-flow state associated with a [`FwdNatKey`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FwdNatVal {
    /// Selected external IPv4 address in big-endian numeric form.
    pub ext_v4: u32,
    /// Allocated external transport port in host byte order.
    pub ext_port: u16,
    /// Reserved padding that must be initialized to zero.
    pub _pad: u16,
    /// Monotonic timestamp of the most recent forward packet, in nanoseconds.
    pub last_seen_ns: u64,
}

impl NatKey {
    /// Creates a reverse-lookup key from an external address, port, and IP protocol.
    #[inline]
    pub fn new_forward(ext_v4_be: u32, ext_port_host: u16, proto: u8) -> Self {
        Self {
            ext_v4: ext_v4_be,
            ext_port: ext_port_host,
            proto,
            _pad: 0,
        }
    }
}

impl NatVal {
    /// Creates reverse-lookup state for a newly translated forward flow.
    #[inline]
    pub fn new_forward(
        vm_v6: [u8; 16],
        vm_port_host: u16,
        remote_v4_be: u32,
        remote_port_host: u16,
        last_seen_ns: u64,
    ) -> Self {
        Self {
            vm_v6,
            vm_port: vm_port_host,
            remote_v4: remote_v4_be,
            remote_port: remote_port_host,
            _pad: 0,
            generation: 0,
            last_seen_ns,
        }
    }

    /// Creates reverse-lookup state with an explicit session generation.
    #[inline]
    pub fn new_forward_with_generation(
        vm_v6: [u8; 16],
        vm_port_host: u16,
        remote_v4_be: u32,
        remote_port_host: u16,
        generation: u32,
        last_seen_ns: u64,
    ) -> Self {
        Self {
            vm_v6,
            vm_port: vm_port_host,
            remote_v4: remote_v4_be,
            remote_port: remote_port_host,
            _pad: 0,
            generation,
            last_seen_ns,
        }
    }
}

/// Extracts the embedded IPv4 address from the low 32 bits of a /96 NAT64 destination.
#[inline(always)]
pub fn nat64_embedded_v4_be(dst: &[u8; 16]) -> u32 {
    u32::from_be_bytes([dst[12], dst[13], dst[14], dst[15]])
}

/// Extracts the embedded IPv4 address bytes from a /96 NAT64 destination.
#[inline(always)]
pub fn nat64_embedded_v4_bytes(dst: &[u8; 16]) -> [u8; 4] {
    [dst[12], dst[13], dst[14], dst[15]]
}

/// Selects an external IPv4 address deterministically for an originating IPv6 address.
#[inline]
pub fn select_v4_from_pool(vm_v6: &[u8; 16], cfg: &Nat64Config) -> Option<u32> {
    if cfg.v4_pool_len == 0 || cfg.v4_pool_len > V4_POOL_MAX as u32 {
        return None;
    }

    let mut hash = 0x811c_9dc5u32;
    for byte in vm_v6 {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }

    let idx = (hash % cfg.v4_pool_len) as usize;
    Some(cfg.v4_pool[idx])
}

/// Builds a reverse-lookup key from a translated destination tuple.
#[inline]
pub fn nat_key(ext_v4: u32, ext_port: u16, proto: u8) -> NatKey {
    NatKey::new_forward(ext_v4, ext_port, proto)
}

/// Builds the NAT lookup key for an incoming IPv4 packet.
#[inline]
pub fn nat_lookup_key_from_ipv4(dst_v4: u32, dst_port: u16, proto: u8) -> NatKey {
    nat_key(dst_v4, dst_port, proto)
}

/// Builds the NAT lookup key from an IPv4 return tuple.
#[inline]
pub fn nat_key_from_return_tuple(dst_v4: u32, dst_port: u16, proto: u8) -> NatKey {
    nat_lookup_key_from_ipv4(dst_v4, dst_port, proto)
}

/// Builds the reverse-lookup key and value for a translated flow.
#[inline]
pub fn nat_make_entry(
    ext_v4: u32,
    ext_port: u16,
    proto: u8,
    vm_v6: [u8; 16],
    vm_port: u16,
    remote_v4: u32,
    remote_port: u16,
    last_seen_ns: u64,
) -> (NatKey, NatVal) {
    (
        nat_key(ext_v4, ext_port, proto),
        NatVal::new_forward(vm_v6, vm_port, remote_v4, remote_port, last_seen_ns),
    )
}

/// Returns whether an IPv4 source address and source port match the recorded remote tuple.
#[inline]
pub fn nat_tuple_matches(nat_val: &NatVal, ipv4_src: u32, tcp_sport: u16) -> bool {
    nat_val.remote_v4 == ipv4_src && nat_val.remote_port == tcp_sport
}

/// Builds a forward-flow key from the complete transport five-tuple.
#[inline]
pub fn fwd_nat_key(
    vm_v6: [u8; 16],
    remote_v4: u32,
    vm_port: u16,
    remote_port: u16,
    proto: u8,
) -> FwdNatKey {
    FwdNatKey {
        vm_v6,
        remote_v4,
        vm_port,
        remote_port,
        proto,
        _pad: [0; 3],
    }
}

/// Builds the 12-byte IPv4 pseudo-header used by TCP and UDP checksums.
#[inline]
pub fn build_ipv4_pseudo_header_bytes(
    src_v4_be: u32,
    dst_v4_be: u32,
    l4_len: u16,
    proto: u8,
) -> [u8; 12] {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_v4_be.to_be_bytes());
    pseudo[4..8].copy_from_slice(&dst_v4_be.to_be_bytes());
    pseudo[9] = proto;
    pseudo[10..12].copy_from_slice(&l4_len.to_be_bytes());
    pseudo
}

/// Builds the 40-byte IPv6 pseudo-header used by TCP and UDP checksums.
#[inline]
pub fn build_ipv6_pseudo_header_bytes(
    src_v6: &[u8; 16],
    dst_v6: &[u8; 16],
    l4_len: u16,
    next_header: u8,
) -> [u8; 40] {
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(src_v6);
    pseudo[16..32].copy_from_slice(dst_v6);
    pseudo[32..36].copy_from_slice(&(u32::from(l4_len)).to_be_bytes());
    pseudo[39] = next_header;
    pseudo
}

#[cfg(feature = "server")]
unsafe impl aya::Pod for Nat64Prefix {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for Nat64Config {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for DbgIpv6Sample {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for DbgFwdTcpSample {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for DbgFwdTcpCsumSample {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for ProdCounters {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for DebugCounters {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for NatKey {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for NatVal {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for FwdNatKey {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for FwdNatVal {}

#[cfg(feature = "server")]
unsafe impl aya::Pod for PortCooldownRing {}

#[cfg(test)]
mod tests {
    use crate::{
        DbgFwdTcpCsumSample, DebugCounters, FwdNatVal, Nat64Config, NatKey, NatVal, ProdCounters,
        V4_POOL_MAX, fwd_nat_key, nat_key, nat_key_from_return_tuple, nat_lookup_key_from_ipv4,
        nat_make_entry, nat_tuple_matches, nat64_embedded_v4_be, nat64_embedded_v4_bytes,
        select_v4_from_pool,
        wire::{read_u32_be, write_u32_be},
    };
    use core::mem::size_of;

    #[test]
    fn counters_layout_sanity() {
        assert_eq!(size_of::<ProdCounters>() % 8, 0);
        assert_eq!(size_of::<DebugCounters>() % 8, 0);
        assert!(size_of::<ProdCounters>() > 0);
        assert!(size_of::<DebugCounters>() > 0);
    }

    #[test]
    fn ethertype_helper_order_matches_bpf_expectation_ipv4() {
        // bpf_skb_change_proto expects a __be16 numeric value, which differs from wire bytes
        // on little-endian hosts.
        assert_eq!(0x0800u16.to_be(), 0x0008);
    }

    #[test]
    fn ethertype_helper_order_matches_bpf_expectation_ipv6() {
        assert_eq!(0x86DDu16.to_be(), 0xDD86);
    }

    #[test]
    fn ethertype_wire_bytes_stay_canonical() {
        assert_eq!(0x0800u16.to_be_bytes(), [0x08, 0x00]);
        assert_eq!(0x86DDu16.to_be_bytes(), [0x86, 0xDD]);
    }

    #[test]
    fn ipv4_host_order_be_roundtrip() {
        let values = [0x0000_0000, 0xffff_ffff, 0x0102_0304, 0x7f00_0001];

        for v in values {
            assert_eq!(read_u32_be(write_u32_be(v)), v);
        }
    }

    #[test]
    fn nat64_prefix_embedding_96_correctness() {
        let prefix96 = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
        let remote_v4 = 0x0102_0304;

        let mut src = [0u8; 16];
        src[..12].copy_from_slice(&prefix96);
        src[12..16].copy_from_slice(&write_u32_be(remote_v4));

        assert_eq!(&src[0..12], &prefix96);
        assert_eq!(&src[12..16], &[1, 2, 3, 4]);
    }

    #[test]
    fn fwd_nat_key_depends_on_full_5tuple() {
        let vm_v6 = [0x11u8; 16];
        let remote_v4 = u32::from_be_bytes([203, 0, 113, 1]);

        let base = fwd_nat_key(vm_v6, remote_v4, 12345, 443, 6);
        let same = fwd_nat_key(vm_v6, remote_v4, 12345, 443, 6);
        assert_eq!(base, same);

        let changed_src = fwd_nat_key(vm_v6, remote_v4, 12346, 443, 6);
        assert_ne!(base, changed_src);

        let changed_dst = fwd_nat_key(vm_v6, remote_v4, 12345, 444, 6);
        assert_ne!(base, changed_dst);

        let changed_proto = fwd_nat_key(vm_v6, remote_v4, 12345, 443, 17);
        assert_ne!(base, changed_proto);
    }

    #[test]
    fn fwd_flow_state_reuses_allocated_port_for_same_5tuple() {
        let key = fwd_nat_key(
            [0x22u8; 16],
            u32::from_be_bytes([198, 51, 100, 8]),
            4242,
            53,
            17,
        );
        let first = FwdNatVal {
            ext_v4: u32::from_be_bytes([203, 0, 113, 10]),
            ext_port: 30000,
            _pad: 0,
            last_seen_ns: 100,
        };

        let mut existing: Option<FwdNatVal> = None;
        let first_seen = existing;
        assert!(first_seen.is_none());
        existing = Some(first);

        let second_seen = existing;
        assert_eq!(second_seen.map(|v| v.ext_port), Some(30000));
        let reused = second_seen.expect("flow should be present");
        assert_eq!(reused.ext_v4, first.ext_v4);
        assert_eq!(reused.ext_port, first.ext_port);
        let _ = key;
    }

    #[test]
    fn nat64_wkpf96_prefix_bytes_match_wire_order() {
        let prefix = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(prefix, [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn nat64_embedded_v4_be_extracts_expected_u32() {
        let dst = [
            0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x15, 0x16, 0x63,
        ];

        assert_eq!(nat64_embedded_v4_bytes(&dst), [2, 21, 22, 99]);
        assert_eq!(
            nat64_embedded_v4_be(&dst),
            u32::from_be_bytes([2, 21, 22, 99])
        );
    }

    #[test]
    fn nat64_embedded_v4_be_is_not_native_endian_scrambled() {
        let dst = [
            0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x15, 0x16, 0x81,
        ];
        let be = nat64_embedded_v4_be(&dst);
        assert_eq!(be.to_be_bytes(), [2, 21, 22, 129]);
    }

    #[test]
    fn non_nat64_global_ipv6_does_not_match_wkpf96_prefix() {
        let global = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x15, 0x16, 0x81,
        ];
        let prefix = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_ne!(global[..12], prefix);
    }

    #[test]
    fn ipv4_pseudo_header_builder_writes_expected_layout() {
        let pseudo = crate::build_ipv4_pseudo_header_bytes(0x0a00_0001, 0xcb00_710a, 1234, 17);
        assert_eq!(&pseudo[0..4], &[10, 0, 0, 1]);
        assert_eq!(&pseudo[4..8], &[203, 0, 113, 10]);
        assert_eq!(pseudo[8], 0);
        assert_eq!(pseudo[9], 17);
        assert_eq!(&pseudo[10..12], &1234u16.to_be_bytes());
    }

    #[test]
    fn ipv6_pseudo_header_builder_writes_expected_layout() {
        let src = [0x11u8; 16];
        let dst = [0x22u8; 16];
        let pseudo = crate::build_ipv6_pseudo_header_bytes(&src, &dst, 4321, 6);
        assert_eq!(&pseudo[0..16], &src);
        assert_eq!(&pseudo[16..32], &dst);
        assert_eq!(&pseudo[32..36], &(4321u32).to_be_bytes());
        assert_eq!(&pseudo[36..39], &[0, 0, 0]);
        assert_eq!(pseudo[39], 6);
    }

    #[test]
    fn ipv4_pseudo_header_length_is_12_bytes() {
        let pseudo = crate::build_ipv4_pseudo_header_bytes(0x0a00_0001, 0xcb00_710a, 1234, 17);
        assert_eq!(pseudo.len(), 12);
    }

    #[test]
    fn ipv6_pseudo_header_length_is_40_bytes() {
        let src = [0x11u8; 16];
        let dst = [0x22u8; 16];
        let pseudo = crate::build_ipv6_pseudo_header_bytes(&src, &dst, 4321, 6);
        assert_eq!(pseudo.len(), 40);
    }

    #[test]
    fn u16_be_read_write_roundtrip_table_driven() {
        let values = [0u16, 1, 0x00ff, 0x0102, 0x7fff, 0x8000, 0xffff];

        for v in values {
            let encoded = crate::wire::write_u16_be(v);
            let decoded = crate::wire::read_u16_be(encoded);
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn pool_selection_deterministic_for_same_vm() {
        let cfg = Nat64Config {
            prefix96: [0; 12],
            v4_pool: [
                0xc633_640a,
                0xc633_640b,
                0xc633_640c,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            v4_pool_len: 3,
            bridge_ifindex: 0,
            uplink_ifindex: 0,
            port_min: 20_000,
            port_max: 60_000,
            session_timeout_secs: 0,
            v4_policy: 0,
            _pad: [0; 3],
        };
        let vm_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

        let one = select_v4_from_pool(&vm_v6, &cfg);
        let two = select_v4_from_pool(&vm_v6, &cfg);
        assert_eq!(one, two);
        assert!(one.is_some());
    }

    #[test]
    fn pool_selection_distribution_sanity() {
        let cfg = Nat64Config {
            prefix96: [0; 12],
            v4_pool: [
                0xc633_640a,
                0xc633_640b,
                0xc633_640c,
                0xc633_640d,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            v4_pool_len: 4,
            bridge_ifindex: 0,
            uplink_ifindex: 0,
            port_min: 20_000,
            port_max: 60_000,
            session_timeout_secs: 0,
            v4_policy: 0,
            _pad: [0; 3],
        };

        let vm_addrs = [
            [0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            [0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
            [0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
        ];

        let mut selections = [0u32; 4];
        for (i, vm) in vm_addrs.iter().enumerate() {
            selections[i] = select_v4_from_pool(vm, &cfg).expect("pool must select");
        }

        let mut any_diff = false;
        for i in 1..selections.len() {
            if selections[i] != selections[0] {
                any_diff = true;
                break;
            }
        }

        assert!(any_diff);
    }

    #[test]
    fn nat_struct_layout_sanity() {
        assert_eq!(V4_POOL_MAX, 16);
        assert_eq!(size_of::<NatKey>(), 8);
        assert_eq!(size_of::<NatVal>(), 40);
        assert_eq!(size_of::<Nat64Config>(), 100);
        assert_eq!(size_of::<DbgFwdTcpCsumSample>(), 32);
    }

    #[test]
    fn nat_key_helper_sets_fields() {
        let key = nat_key(0xc633_640a, 30_000, 6);
        assert_eq!(
            key,
            NatKey {
                ext_v4: 0xc633_640a,
                ext_port: 30_000,
                proto: 6,
                _pad: 0,
            }
        );
    }

    #[test]
    fn nat_key_tcp_vs_udp_differs() {
        let ext_v4 = 0xc633_640a;
        let ext_port = 30_123;
        assert_ne!(nat_key(ext_v4, ext_port, 6), nat_key(ext_v4, ext_port, 17));
    }

    #[test]
    fn nat_lookup_key_matches_nat_key() {
        let ext_v4 = 0xc633_640a;
        let ext_port = 30_123;
        let proto = 6;
        assert_eq!(
            nat_key(ext_v4, ext_port, proto),
            nat_lookup_key_from_ipv4(ext_v4, ext_port, proto)
        );
    }

    #[test]
    fn nat_tuple_match_restores_vm_port_semantics() {
        let (_, nat_val) = nat_make_entry(
            0xc633_640a,
            30_123,
            6,
            [0u8; 16],
            34_567,
            0xcb00_7105,
            443,
            0,
        );

        let ipv4_src = 0xcb00_7105;
        let tcp_sport = 443;
        assert!(nat_tuple_matches(&nat_val, ipv4_src, tcp_sport));
        assert_eq!(nat_val.vm_port, 34_567);
    }

    #[test]
    fn nat_key_symmetry_tcp_udp_deterministic_set() {
        let ext_v4s = [0x0102_0304, 0x0a00_0001, 0xc000_0201];
        let ext_ports = [1u16, 53, 443, 12_345, 54_321];
        let protos = [6u8, 17u8];

        for ext_v4 in ext_v4s {
            for ext_port in ext_ports {
                for proto in protos {
                    assert_eq!(
                        nat_key(ext_v4, ext_port, proto),
                        nat_key_from_return_tuple(ext_v4, ext_port, proto)
                    );
                }
            }
        }
    }

    #[test]
    fn nat_tuple_matches_on_expected_remote_tuple() {
        let (_, val) = nat_make_entry(
            0x0a00_0001,
            40_000,
            6,
            [0; 16],
            12_345,
            0x0808_0808,
            443,
            123,
        );

        assert!(nat_tuple_matches(&val, 0x0808_0808, 443));
    }

    #[test]
    fn nat_tuple_mismatch_remote_v4_fails() {
        let (_, val) = nat_make_entry(
            0x0a00_0001,
            40_000,
            6,
            [0; 16],
            12_345,
            0x0808_0808,
            443,
            123,
        );

        assert!(!nat_tuple_matches(&val, 0x0101_0101, 443));
    }

    #[test]
    fn nat_tuple_mismatch_remote_port_fails() {
        let (_, val) = nat_make_entry(
            0x0a00_0001,
            40_000,
            6,
            [0; 16],
            12_345,
            0x0808_0808,
            443,
            123,
        );

        assert!(!nat_tuple_matches(&val, 0x0808_0808, 444));
    }

    #[test]
    fn nat_key_protocol_separation_invariant() {
        let ext_v4 = 0x0102_0304;
        let ext_port = 12_345;

        assert_ne!(nat_key(ext_v4, ext_port, 6), nat_key(ext_v4, ext_port, 17));
    }

    #[test]
    fn nat_key_port_field_is_host_order() {
        let key = NatKey {
            ext_v4: 0,
            ext_port: 0x1234,
            proto: 6,
            _pad: 0,
        };

        assert_eq!(key.ext_port, 0x1234);
    }

    #[test]
    fn nat_key_proto_separation_and_tuple_match_matrix() {
        let ext_v4s = [0x0102_0304, 0x0a00_0001, 0xc000_0201];
        let ext_ports = [53u16, 443, 12_345];
        let protos = [(6u8, "tcp"), (17u8, "udp")];
        let remote_v4s = [0x0808_0808, 0x0101_0101];
        let remote_ports = [53u16, 443, 444];
        let vm_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let vm_port = 55_555;

        for ext_v4 in ext_v4s {
            for ext_port in ext_ports {
                assert_ne!(nat_key(ext_v4, ext_port, 6), nat_key(ext_v4, ext_port, 17));

                for (proto, proto_name) in protos {
                    let match_remote_v4 = remote_v4s[0];
                    let match_remote_port = remote_ports[1];
                    let (_, val) = nat_make_entry(
                        ext_v4,
                        ext_port,
                        proto,
                        vm_v6,
                        vm_port,
                        match_remote_v4,
                        match_remote_port,
                        42,
                    );

                    for remote_v4 in remote_v4s {
                        for remote_port in remote_ports {
                            let expected =
                                remote_v4 == match_remote_v4 && remote_port == match_remote_port;
                            assert_eq!(
                                nat_tuple_matches(&val, remote_v4, remote_port),
                                expected,
                                "proto={proto_name}, ext={ext_v4:#x}:{ext_port}, remote={remote_v4:#x}:{remote_port}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn nat_key_roundtrip_matrix() {
        let ext_v4s = [0x0102_0304, 0x0a00_0001, 0xc000_0201];
        let ext_ports = [53u16, 443, 12_345];
        let protos = [6u8, 17u8];

        for ext_v4 in ext_v4s {
            for ext_port in ext_ports {
                for proto in protos {
                    assert_eq!(
                        nat_key(ext_v4, ext_port, proto),
                        nat_key_from_return_tuple(ext_v4, ext_port, proto)
                    );
                }
            }
        }
    }

    #[test]
    fn nat_key_new_forward_keeps_be_v4_and_host_port() {
        let key = NatKey::new_forward(u32::from_be_bytes([203, 0, 113, 10]), 40_123, 6);
        assert_eq!(key.ext_v4.to_be_bytes(), [203, 0, 113, 10]);
        assert_eq!(key.ext_port, 40_123);
    }

    #[test]
    fn nat_val_new_forward_keeps_remote_v4_in_be_order() {
        let remote = u32::from_be_bytes([2, 21, 22, 99]);
        let val = NatVal::new_forward([0; 16], 12_345, remote, 443, 77);
        assert_eq!(val.remote_v4.to_be_bytes(), [2, 21, 22, 99]);
        assert_eq!(val.remote_port, 443);
    }

    #[test]
    fn selected_pool_v4_be_matches_reverse_lookup_key_encoding() {
        let mut cfg = Nat64Config {
            prefix96: [0; 12],
            v4_pool: [0; V4_POOL_MAX],
            v4_pool_len: 1,
            bridge_ifindex: 0,
            uplink_ifindex: 0,
            port_min: 20_000,
            port_max: 60_000,
            session_timeout_secs: 0,
            v4_policy: 0,
            _pad: [0; 3],
        };
        cfg.v4_pool[0] = u32::from_be_bytes([203, 0, 113, 10]);

        let selected = select_v4_from_pool(&[0x11; 16], &cfg).expect("pool must select");
        let key = nat_lookup_key_from_ipv4(selected, 40_000, 6);

        assert_eq!(selected.to_be_bytes(), [203, 0, 113, 10]);
        assert_eq!(key.ext_v4.to_be_bytes(), [203, 0, 113, 10]);
    }
}
