#![no_std]
//! eBPF traffic-control classifiers implementing stateful bidirectional NAT64 translation.

mod ipv6;

use aya_ebpf::helpers::{bpf_printk, generated::bpf_csum_diff};
use aya_ebpf::{
    bindings::{BPF_F_MARK_MANGLED_0, BPF_F_PSEUDO_HDR, TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_SHOT},
    btf_maps::LruHashMap as BtfLruHashMap,
    macros::{btf_map, classifier, map},
    maps::{HashMap, LruHashMap, PerCpuArray},
    programs::TcContext,
};
use aya_ebpf_bindings::{
    bindings::bpf_timer,
    helpers::{bpf_redirect_neigh, bpf_timer_init, bpf_timer_set_callback, bpf_timer_start},
};
use nat64_common::{
    CONFIG_KEY, COOLDOWN_SIZE, DBG_FWD_DST_SAMPLE_SLOTS, DBG_FWD_TCP_CSUM_SAMPLE_SLOTS,
    DBG_FWD_TCP_SAMPLE_SLOTS, DbgFwdTcpCsumSample, DbgFwdTcpSample, DbgIpv6Sample, DebugCounters,
    FwdNatKey, Nat64Config, NatKey, NatVal, PortCooldownRing, ProdCounters, V4_POOL_MAX,
    V4_SELECT_POLICY_HASH_VM_V6, build_ipv4_pseudo_header_bytes, build_ipv6_pseudo_header_bytes,
    nat_key, nat_lookup_key_from_ipv4, nat_tuple_matches, nat64_embedded_v4_be,
    nat64_embedded_v4_bytes,
};

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
// __be16 numeric values expected by bpf_skb_change_proto helper arguments.
const ETH_P_IP_HELPER: u16 = ETH_P_IP.to_be();
const ETH_P_IPV6_HELPER: u16 = ETH_P_IPV6.to_be();
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const UDP_HDR_LEN: usize = 8;
const DEFAULT_NAT64_PREFIX: [u8; 12] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
const DEFAULT_V4_SRC: u32 = u32::from_be_bytes([203, 0, 113, 10]);
const DEFAULT_PORT_MIN: u16 = 20_000;
const DEFAULT_PORT_MAX: u16 = 60_000;
const DEFAULT_CFG: Nat64Config = Nat64Config {
    prefix96: DEFAULT_NAT64_PREFIX,
    v4_pool: [DEFAULT_V4_SRC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    v4_pool_len: 1,
    port_min: DEFAULT_PORT_MIN,
    port_max: DEFAULT_PORT_MAX,
    session_timeout_secs: 0,
    v4_policy: V4_SELECT_POLICY_HASH_VM_V6,
    bridge_ifindex: 0,
    uplink_ifindex: 0,
    _pad: [0; 3],
};
const NAT64_WKPF_PREFIX: [u8; 12] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
const MAX_L4_LEN: usize = 1500;
const CLOCK_MONOTONIC: u64 = 1;
const EXPIRY_CONFIRMATION_NS: u64 = 10_000_000;

#[repr(C)]
struct TimedFwdNatVal {
    ext_v4: u32,
    ext_port: u16,
    _pad: u16,
    last_seen_ns: u64,
    generation: u32,
    _pad2: u32,
    observed_last_seen_ns: u64,
    timer: bpf_timer,
}

impl TimedFwdNatVal {
    #[inline(always)]
    fn new(ext_v4: u32, ext_port: u16, generation: u32, last_seen_ns: u64) -> Self {
        Self {
            ext_v4,
            ext_port,
            _pad: 0,
            last_seen_ns,
            generation,
            _pad2: 0,
            observed_last_seen_ns: 0,
            timer: unsafe { core::mem::zeroed() },
        }
    }
}
#[map]
static CONFIG: HashMap<u32, Nat64Config> = HashMap::with_max_entries(1, 0);

#[map]
static PROD_COUNTERS: PerCpuArray<ProdCounters> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DEBUG_COUNTERS: PerCpuArray<DebugCounters> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NAT: LruHashMap<NatKey, NatVal> = LruHashMap::with_max_entries(262_144, 0);

#[btf_map]
static FWD_NAT: BtfLruHashMap<FwdNatKey, TimedFwdNatVal, 262_144> = BtfLruHashMap::new();

#[map]
static PORT_CURSOR: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PORT_COOLDOWN: PerCpuArray<PortCooldownRing> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DBG_FWD_DST_SAMPLES: PerCpuArray<DbgIpv6Sample> =
    PerCpuArray::with_max_entries(DBG_FWD_DST_SAMPLE_SLOTS, 0);

#[map]
static DBG_FWD_DST_SAMPLE_CURSOR: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DBG_FWD_TCP_SAMPLES: PerCpuArray<DbgFwdTcpSample> =
    PerCpuArray::with_max_entries(DBG_FWD_TCP_SAMPLE_SLOTS, 0);

#[map]
static DBG_FWD_TCP_SAMPLE_CURSOR: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DBG_FWD_TCP_CSUM_SAMPLES: PerCpuArray<DbgFwdTcpCsumSample> =
    PerCpuArray::with_max_entries(DBG_FWD_TCP_CSUM_SAMPLE_SLOTS, 0);

#[map]
static DBG_FWD_TCP_CSUM_SAMPLE_CURSOR: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DBG_CHANGE_PROTO_FAIL_PRINT_FWD: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DBG_CHANGE_PROTO_FAIL_PRINT_REV: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn session_timeout_ns(cfg: &Nat64Config) -> u64 {
    u64::from(cfg.session_timeout_secs).saturating_mul(1_000_000_000)
}

#[inline(always)]
fn timer_rearm(timer: *mut bpf_timer, delay_ns: u64) -> bool {
    unsafe { bpf_timer_start(timer, delay_ns.max(1), 0) == 0 }
}

unsafe extern "C" fn session_timer_callback(
    _map: *mut core::ffi::c_void,
    key: *mut FwdNatKey,
    value: *mut TimedFwdNatVal,
) -> i32 {
    if key.is_null() || value.is_null() {
        return 0;
    }

    let cfg = unsafe { CONFIG.get(&CONFIG_KEY) }.unwrap_or(&DEFAULT_CFG);
    let timeout_ns = session_timeout_ns(cfg);
    if timeout_ns == 0 {
        return 0;
    }

    let key_copy = unsafe { *key };
    let generation = unsafe { (*value).generation };
    let reverse_key = nat_key(
        unsafe { (*value).ext_v4 },
        unsafe { (*value).ext_port },
        key_copy.proto,
    );
    let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let fwd_last_seen = unsafe { (*value).last_seen_ns };
    let reverse_last_seen = unsafe { NAT.get(&reverse_key) }
        .filter(|reverse| reverse.generation == generation)
        .map(|reverse| reverse.last_seen_ns)
        .unwrap_or(0);
    let latest = fwd_last_seen.max(reverse_last_seen);
    let elapsed = now_ns.saturating_sub(latest);

    if elapsed < timeout_ns {
        unsafe { (*value).observed_last_seen_ns = 0 };
        let _ = timer_rearm(
            unsafe { core::ptr::addr_of_mut!((*value).timer) },
            timeout_ns - elapsed,
        );
        return 0;
    }

    // A second callback after a short quiescence interval sharply narrows the
    // refresh-versus-delete race without adding a lock or lookup to packets.
    if unsafe { (*value).observed_last_seen_ns } != latest {
        unsafe { (*value).observed_last_seen_ns = latest };
        let _ = timer_rearm(
            unsafe { core::ptr::addr_of_mut!((*value).timer) },
            EXPIRY_CONFIRMATION_NS,
        );
        return 0;
    }

    let final_fwd_last_seen = unsafe { (*value).last_seen_ns };
    let final_reverse = unsafe { NAT.get(&reverse_key) }.copied();
    let final_reverse_last_seen = final_reverse
        .filter(|reverse| reverse.generation == generation)
        .map(|reverse| reverse.last_seen_ns)
        .unwrap_or(0);
    let final_latest = final_fwd_last_seen.max(final_reverse_last_seen);
    if final_latest != latest || now_ns.saturating_sub(final_latest) < timeout_ns {
        unsafe { (*value).observed_last_seen_ns = 0 };
        let delay = timeout_ns.saturating_sub(now_ns.saturating_sub(final_latest));
        let _ = timer_rearm(unsafe { core::ptr::addr_of_mut!((*value).timer) }, delay);
        return 0;
    }

    if final_reverse.is_some_and(|reverse| reverse.generation == generation) {
        let _ = NAT.remove(&reverse_key);
    }
    let _ = FWD_NAT.remove(&key_copy);
    0
}

#[inline(always)]
fn arm_session_timer(key: &FwdNatKey) -> bool {
    let Some(value) = FWD_NAT.get_ptr_mut(key) else {
        return false;
    };
    let timer = unsafe { core::ptr::addr_of_mut!((*value).timer) };
    let map = core::ptr::addr_of!(FWD_NAT).cast_mut().cast();
    if unsafe { bpf_timer_init(timer, map, CLOCK_MONOTONIC) } != 0 {
        return false;
    }
    if unsafe { bpf_timer_set_callback(timer, session_timer_callback as *mut core::ffi::c_void) }
        != 0
    {
        return false;
    }
    let cfg = unsafe { CONFIG.get(&CONFIG_KEY) }.unwrap_or(&DEFAULT_CFG);
    timer_rearm(timer, session_timeout_ns(cfg))
}

#[inline(always)]
fn lookup_or_create_mapping(
    cfg: &Nat64Config,
    key: &FwdNatKey,
    selected_ext_v4: u32,
    proto: u8,
    now_ns: u64,
) -> Option<(u32, u16, u32)> {
    if let Some(existing) = FWD_NAT.get_ptr_mut(key) {
        let (ext_v4, ext_port, generation) = unsafe {
            (*existing).last_seen_ns = now_ns;
            (*existing).observed_last_seen_ns = 0;
            (
                (*existing).ext_v4,
                (*existing).ext_port,
                (*existing).generation,
            )
        };
        with_counters(|prod, _| {
            prod.fwd_nat_lookup_hit = prod.fwd_nat_lookup_hit.saturating_add(1);
            prod.fwd_nat_refresh_ok = prod.fwd_nat_refresh_ok.saturating_add(1);
        });
        return Some((ext_v4, ext_port, generation));
    }

    with_counters(|prod, _| prod.fwd_nat_lookup_miss = prod.fwd_nat_lookup_miss.saturating_add(1));
    let ext_port = match alloc_port(cfg, selected_ext_v4, proto) {
        Some(port) => {
            with_counters(|prod, _| prod.port_alloc_ok = prod.port_alloc_ok.saturating_add(1));
            port
        }
        None => {
            with_counters(|prod, _| prod.port_alloc_err = prod.port_alloc_err.saturating_add(1));
            return None;
        }
    };
    let generation = unsafe { aya_ebpf::helpers::bpf_get_prandom_u32() };
    let value = TimedFwdNatVal::new(selected_ext_v4, ext_port, generation, now_ns);
    if FWD_NAT.insert(key, &value, 0).is_err() {
        with_counters(|prod, _| {
            prod.fwd_nat_insert_err = prod.fwd_nat_insert_err.saturating_add(1)
        });
        return None;
    }

    if cfg.session_timeout_secs != 0 && !arm_session_timer(key) {
        let _ = FWD_NAT.remove(key);
        with_counters(|prod, _| {
            prod.fwd_nat_insert_err = prod.fwd_nat_insert_err.saturating_add(1)
        });
        return None;
    }

    with_counters(|prod, _| prod.fwd_nat_insert_ok = prod.fwd_nat_insert_ok.saturating_add(1));
    Some((selected_ext_v4, ext_port, generation))
}

/// Translates matching IPv6 TCP and UDP traffic to IPv4 and redirects it to the configured uplink.
#[classifier]
pub fn nat64_forward(ctx: TcContext) -> i32 {
    match try_nat64_forward(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn fwd_nat_key(
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

#[inline(always)]
fn try_nat64_forward(mut ctx: TcContext) -> Result<i32, i32> {
    with_counters(|prod, debug| {
        debug.dbg_fwd_enter = debug.dbg_fwd_enter.saturating_add(1);
        prod.pkts_total = prod.pkts_total.saturating_add(1);
    });

    let ether_type_be = ctx.load::<u16>(12).map_err(|_| TC_ACT_PIPE)?;
    if u16::from_be(ether_type_be) != ETH_P_IPV6 {
        with_counters(|prod, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    with_counters(|prod, debug| {
        debug.dbg_fwd_eth_ipv6 = debug.dbg_fwd_eth_ipv6.saturating_add(1);
        prod.pkts_ipv6 = prod.pkts_ipv6.saturating_add(1);
    });

    let ipv6_info = match ipv6::parse_ipv6_base(&ctx, ETH_HDR_LEN) {
        Ok(info) => {
            with_counters(|prod, debug| {
                debug.pkts_ipv6_parsed_ok = debug.pkts_ipv6_parsed_ok.saturating_add(1);
            });
            info
        }
        Err(ipv6::Ipv6ParseError::Truncated) => return Ok(TC_ACT_PIPE),
    };

    let has_extension_header = ipv6::is_extension_header(ipv6_info.next_header);
    if has_extension_header {
        with_counters(|prod, debug| {
            debug.pkts_ipv6_ext_hdr = debug.pkts_ipv6_ext_hdr.saturating_add(1);
        });
    } else if ipv6_info.next_header != IPPROTO_TCP && ipv6_info.next_header != IPPROTO_UDP {
        with_counters(|prod, debug| {
            debug.pkts_ipv6_non_tcp_udp = debug.pkts_ipv6_non_tcp_udp.saturating_add(1);
        });
    } else if ipv6_info.next_header == IPPROTO_UDP {
        with_counters(|prod, debug| {
            debug.pkts_udp = debug.pkts_udp.saturating_add(1);
        });
    }

    record_fwd_dst_sample(&ipv6_info.dst);
    classify_fwd_dst(&ipv6_info.dst);

    let cfg: &Nat64Config = unsafe { CONFIG.get(&CONFIG_KEY) }.unwrap_or(&DEFAULT_CFG);
    if ipv6_info.dst[..12] != cfg.prefix96 {
        with_counters(|prod, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    with_counters(|prod, debug| {
        debug.dbg_fwd_nat64_prefix_match = debug.dbg_fwd_nat64_prefix_match.saturating_add(1);
        prod.pkts_nat64_dst = prod.pkts_nat64_dst.saturating_add(1);
    });

    if has_extension_header {
        with_counters(|prod, debug| {
            prod.unsupported_ipv6_extension_headers =
                prod.unsupported_ipv6_extension_headers.saturating_add(1);
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    if ipv6_info.next_header != IPPROTO_TCP && ipv6_info.next_header != IPPROTO_UDP {
        with_counters(|prod, debug| {
            prod.unsupported_ipv6_non_tcp_udp = prod.unsupported_ipv6_non_tcp_udp.saturating_add(1);
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let remote_v4_bytes = nat64_embedded_v4_bytes(&ipv6_info.dst);
    let remote_v4 = nat64_embedded_v4_be(&ipv6_info.dst);

    let ext_v4 = match select_v4_from_pool_ebpf(&ipv6_info.src, cfg) {
        Some(v4) => v4,
        None => return Ok(TC_ACT_PIPE),
    };

    if ipv6_info.next_header == IPPROTO_TCP {
        with_counters(|prod, debug| {
            debug.dbg_fwd_tcp_branch = debug.dbg_fwd_tcp_branch.saturating_add(1);
            prod.pkts_nat64_tcp = prod.pkts_nat64_tcp.saturating_add(1);
        });

        let payload_len = ipv6_info.payload_len;
        if usize::from(payload_len) > MAX_L4_LEN {
            with_counters(|prod, debug| {
                prod.nat64_v6_to_v4_err_csum = prod.nat64_v6_to_v4_err_csum.saturating_add(1);
                debug.dbg_fwd_tcp_parse_err = debug.dbg_fwd_tcp_parse_err.saturating_add(1);
                debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }

        if ctx.change_proto(ETH_P_IP_HELPER, 0).is_err() {
            with_counters(|prod, debug| {
                debug.proto_change_err = debug.proto_change_err.saturating_add(1);
                debug.nat64_v6_to_v4_err_change_proto =
                    debug.nat64_v6_to_v4_err_change_proto.saturating_add(1);
                debug.dbg_fwd_adjust_room_err = debug.dbg_fwd_adjust_room_err.saturating_add(1);
                debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
            });
            if should_log_change_proto_fail(true) {
                unsafe {
                    bpf_printk!(
                        c"dbg change_proto fail: target=ipv4 host=0x%x helper=0x%x",
                        ETH_P_IP as u32,
                        ETH_P_IP_HELPER as u32
                    );
                }
            }
            return Ok(TC_ACT_PIPE);
        }
        with_counters(|prod, debug| {
            debug.proto_change_ok = debug.proto_change_ok.saturating_add(1)
        });

        let eth_p_ip = ETH_P_IP.to_be_bytes();
        if ctx.store(12, &eth_p_ip, 0).is_err() {
            with_counters(|prod, debug| {
                debug.nat64_v6_to_v4_err_l2_store =
                    debug.nat64_v6_to_v4_err_l2_store.saturating_add(1);
                debug.dbg_fwd_store_bytes_err = debug.dbg_fwd_store_bytes_err.saturating_add(1);
                debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }

        let tcp_offset = ETH_HDR_LEN + IPV4_HDR_LEN;
        let (tcp_sport, tcp_dport) = match tcp_ports(&ctx, tcp_offset) {
            Ok(ports) => ports,
            Err(()) => {
                with_counters(|prod, debug| {
                    prod.nat64_v6_to_v4_err_csum = prod.nat64_v6_to_v4_err_csum.saturating_add(1);
                    debug.dbg_fwd_tcp_parse_err = debug.dbg_fwd_tcp_parse_err.saturating_add(1);
                    debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
                });
                return Ok(TC_ACT_PIPE);
            }
        };

        let fwd_key = fwd_nat_key(ipv6_info.src, remote_v4, tcp_sport, tcp_dport, IPPROTO_TCP);
        let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let Some((ext_v4, ext_port, generation)) =
            lookup_or_create_mapping(cfg, &fwd_key, ext_v4, IPPROTO_TCP, now_ns)
        else {
            with_counters(|_, debug| {
                debug.dbg_fwd_redirect_or_return_err =
                    debug.dbg_fwd_redirect_or_return_err.saturating_add(1);
                debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        };

        if write_ipv4_header(&mut ctx, payload_len, ext_v4, remote_v4, IPPROTO_TCP).is_err() {
            with_counters(|prod, debug| {
                debug.rewrite_v4_src_err = debug.rewrite_v4_src_err.saturating_add(1);
                prod.nat64_v6_to_v4_err_write_hdr =
                    prod.nat64_v6_to_v4_err_write_hdr.saturating_add(1);
                debug.dbg_fwd_write_ipv4_err = debug.dbg_fwd_write_ipv4_err.saturating_add(1);
                debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }
        with_counters(|prod, debug| {
            debug.rewrite_v4_src_ok = debug.rewrite_v4_src_ok.saturating_add(1)
        });

        let ext_port_be = ext_port.to_be_bytes();
        if ctx.store(tcp_offset, &ext_port_be, 0).is_err() {
            with_counters(|prod, debug| {
                debug.rewrite_tcp_sport_err = debug.rewrite_tcp_sport_err.saturating_add(1);
                prod.nat64_v6_to_v4_err_csum = prod.nat64_v6_to_v4_err_csum.saturating_add(1);
                debug.dbg_fwd_store_bytes_err = debug.dbg_fwd_store_bytes_err.saturating_add(1);
                debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }
        with_counters(|prod, debug| {
            debug.rewrite_tcp_sport_ok = debug.rewrite_tcp_sport_ok.saturating_add(1)
        });

        let csum_trace = match apply_l4_nat64_checksum_delta_v6_to_v4(
            &ctx,
            tcp_offset + 16,
            payload_len,
            IPPROTO_TCP,
            &ipv6_info.src,
            &ipv6_info.dst,
            ext_v4,
            remote_v4,
            Some((tcp_sport, ext_port)),
            false,
        ) {
            Ok(trace) => trace,
            Err(()) => {
                with_counters(|prod, debug| {
                    prod.nat64_v6_to_v4_err_csum = prod.nat64_v6_to_v4_err_csum.saturating_add(1);
                    debug.dbg_fwd_l4_csum_err = debug.dbg_fwd_l4_csum_err.saturating_add(1);
                    debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
                });
                return Ok(TC_ACT_PIPE);
            }
        };

        let nat_val = NatVal::new_forward_with_generation(
            ipv6_info.src,
            tcp_sport,
            remote_v4,
            tcp_dport,
            generation,
            now_ns,
        );
        with_counters(|prod, debug| {});
        let nat_insert_ok = NAT
            .insert(&nat_key(ext_v4, ext_port, IPPROTO_TCP), &nat_val, 0)
            .is_ok();
        if nat_insert_ok {
            with_counters(|prod, debug| {
                debug.nat_insert_ok = debug.nat_insert_ok.saturating_add(1)
            });
        } else {
            with_counters(|prod, debug| {
                debug.nat_insert_err = debug.nat_insert_err.saturating_add(1);
                debug.dbg_fwd_nat_insert_err = debug.dbg_fwd_nat_insert_err.saturating_add(1);
                debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }

        record_fwd_tcp_sample(
            &ipv6_info.dst,
            remote_v4_bytes,
            remote_v4,
            ext_v4,
            tcp_sport,
            tcp_dport,
            nat_insert_ok,
            true,
        );

        with_counters(|prod, debug| {
            prod.nat64_v6_to_v4_ok = prod.nat64_v6_to_v4_ok.saturating_add(1);
            debug.fwd_rewrite_ok_before_redirect =
                debug.fwd_rewrite_ok_before_redirect.saturating_add(1);
        });

        let final_check_be = ctx
            .load::<u16>(tcp_offset + 16)
            .unwrap_or(csum_trace.after_port_be);
        let _ = record_fwd_tcp_csum_sample(
            csum_trace,
            final_check_be,
            tcp_sport.to_be(),
            ext_port.to_be(),
            ext_v4,
            remote_v4,
        );

        return Ok(redirect_to_iface(cfg.uplink_ifindex, true));
    }

    with_counters(|prod, debug| {
        debug.dbg_fwd_udp_branch = debug.dbg_fwd_udp_branch.saturating_add(1);
        prod.pkts_nat64_udp = prod.pkts_nat64_udp.saturating_add(1);
    });

    // NOTE: ipv6_info.l4_abs_offset is an absolute skb offset (includes ETH_HDR_LEN already).
    let udp_offset = ipv6_info.l4_abs_offset;
    let (udp_sport, udp_dport, udp_len) = match udp_ports_len(&ctx, udp_offset) {
        Ok(v) => v,
        Err(ret) => return Ok(ret),
    };

    if usize::from(udp_len) < UDP_HDR_LEN {
        with_counters(|prod, debug| {
            debug.nat64_v6_to_v4_udp_err_len = debug.nat64_v6_to_v4_udp_err_len.saturating_add(1)
        });
        with_counters(|prod, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }
    if usize::from(udp_len) > MAX_L4_LEN {
        with_counters(|prod, debug| {
            debug.nat64_v6_to_v4_udp_err_len = debug.nat64_v6_to_v4_udp_err_len.saturating_add(1)
        });
        with_counters(|prod, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let fwd_key = fwd_nat_key(ipv6_info.src, remote_v4, udp_sport, udp_dport, IPPROTO_UDP);
    let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let Some((ext_v4, ext_port, generation)) =
        lookup_or_create_mapping(cfg, &fwd_key, ext_v4, IPPROTO_UDP, now_ns)
    else {
        with_counters(|_, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    };

    if ctx.change_proto(ETH_P_IP_HELPER, 0).is_err() {
        with_counters(|prod, debug| {
            debug.proto_change_err = debug.proto_change_err.saturating_add(1);
            debug.nat64_v6_to_v4_udp_err_change_proto =
                debug.nat64_v6_to_v4_udp_err_change_proto.saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        if should_log_change_proto_fail(true) {
            unsafe {
                bpf_printk!(
                    c"dbg change_proto fail: target=ipv4 host=0x%x helper=0x%x",
                    ETH_P_IP as u32,
                    ETH_P_IP_HELPER as u32
                );
            }
        }
        return Ok(TC_ACT_PIPE);
    }
    with_counters(|prod, debug| debug.proto_change_ok = debug.proto_change_ok.saturating_add(1));

    let eth_p_ip = ETH_P_IP.to_be_bytes();
    if ctx.store(12, &eth_p_ip, 0).is_err() {
        with_counters(|prod, debug| {
            debug.nat64_v6_to_v4_udp_err_l2_store =
                debug.nat64_v6_to_v4_udp_err_l2_store.saturating_add(1)
        });
        with_counters(|prod, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    if write_ipv4_header(&mut ctx, udp_len, ext_v4, remote_v4, IPPROTO_UDP).is_err() {
        with_counters(|prod, debug| {
            debug.rewrite_v4_src_err = debug.rewrite_v4_src_err.saturating_add(1);
            prod.nat64_v6_to_v4_err_write_hdr = prod.nat64_v6_to_v4_err_write_hdr.saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }
    with_counters(|prod, debug| {
        debug.rewrite_v4_src_ok = debug.rewrite_v4_src_ok.saturating_add(1)
    });

    let udp_v4_offset = ETH_HDR_LEN + IPV4_HDR_LEN;
    if ctx
        .store(udp_v4_offset, &ext_port.to_be_bytes(), 0)
        .is_err()
    {
        with_counters(|prod, debug| {
            debug.nat64_v6_to_v4_udp_err_udp_store =
                debug.nat64_v6_to_v4_udp_err_udp_store.saturating_add(1)
        });
        with_counters(|prod, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    // Verifier/performance note:
    // Do not recompute full TCP/UDP checksums from payload here.
    // NAT64 only changes pseudo-header fields and selected ports,
    // so use incremental checksum update helpers instead.
    if apply_l4_nat64_checksum_delta_v6_to_v4(
        &ctx,
        udp_v4_offset + 6,
        udp_len,
        IPPROTO_UDP,
        &ipv6_info.src,
        &ipv6_info.dst,
        ext_v4,
        remote_v4,
        Some((udp_sport, ext_port)),
        true,
    )
    .is_err()
    {
        with_counters(|prod, debug| {
            debug.nat64_v6_to_v4_udp_err_csum = debug.nat64_v6_to_v4_udp_err_csum.saturating_add(1)
        });
        with_counters(|prod, debug| {
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let nat_val = NatVal {
        vm_v6: ipv6_info.src,
        vm_port: udp_sport,
        remote_v4,
        remote_port: udp_dport,
        _pad: 0,
        generation,
        last_seen_ns: now_ns,
    };
    with_counters(|prod, debug| {});
    if NAT
        .insert(&nat_key(ext_v4, ext_port, IPPROTO_UDP), &nat_val, 0)
        .is_ok()
    {
        with_counters(|prod, debug| {
            debug.nat_insert_ok = debug.nat_insert_ok.saturating_add(1);
            debug.nat_insert_udp_ok = debug.nat_insert_udp_ok.saturating_add(1);
        });
    } else {
        with_counters(|prod, debug| {
            debug.nat_insert_err = debug.nat_insert_err.saturating_add(1);
            debug.nat_insert_udp_err = debug.nat_insert_udp_err.saturating_add(1);
        });
    }

    with_counters(|prod, debug| {
        prod.nat64_v6_to_v4_udp_ok = prod.nat64_v6_to_v4_udp_ok.saturating_add(1);
        debug.fwd_rewrite_ok_before_redirect =
            debug.fwd_rewrite_ok_before_redirect.saturating_add(1);
    });

    Ok(redirect_to_iface(cfg.uplink_ifindex, true))
}

/// Translates matching IPv4 return traffic to IPv6 and redirects it to the configured bridge.
#[classifier]
pub fn nat64_reverse(ctx: TcContext) -> i32 {
    match try_nat64_reverse(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn try_nat64_reverse(mut ctx: TcContext) -> Result<i32, i32> {
    with_counters(|prod, debug| {
        debug.dbg_rev_enter = debug.dbg_rev_enter.saturating_add(1);
        prod.pkts_total = prod.pkts_total.saturating_add(1);
    });

    let ether_type_be = ctx.load::<u16>(12).map_err(|_| TC_ACT_PIPE)?;
    if u16::from_be(ether_type_be) != ETH_P_IP {
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    with_counters(|prod, debug| {
        debug.dbg_rev_eth_ipv4 = debug.dbg_rev_eth_ipv4.saturating_add(1);
        prod.pkts_ipv4 = prod.pkts_ipv4.saturating_add(1);
    });

    let l3_offset = ETH_HDR_LEN;
    let vihl = ctx.load::<u8>(l3_offset).map_err(|_| TC_ACT_PIPE)?;
    if (vihl >> 4) != 4 {
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let ihl_words = (vihl & 0x0f) as usize;
    let ihl_bytes = ihl_words * 4;
    if !(20..=60).contains(&ihl_bytes) {
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let total_len = u16::from_be(ctx.load::<u16>(l3_offset + 2).map_err(|_| TC_ACT_PIPE)?) as usize;
    if total_len < ihl_bytes {
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let frag_off_flags = u16::from_be(ctx.load::<u16>(l3_offset + 6).map_err(|_| TC_ACT_PIPE)?);
    let is_fragment = (frag_off_flags & 0x3fff) != 0;
    if is_fragment {
        with_counters(|prod, debug| {
            debug.nat64_v4_to_v6_udp_err_parse =
                debug.nat64_v4_to_v6_udp_err_parse.saturating_add(1);
        });
    }

    let proto = ctx.load::<u8>(l3_offset + 9).map_err(|_| TC_ACT_PIPE)?;
    let ipv4_src = u32::from_be(ctx.load::<u32>(l3_offset + 12).map_err(|_| TC_ACT_PIPE)?);
    let ipv4_dst = u32::from_be(ctx.load::<u32>(l3_offset + 16).map_err(|_| TC_ACT_PIPE)?);

    let cfg: &Nat64Config = unsafe { CONFIG.get(&CONFIG_KEY) }.unwrap_or(&DEFAULT_CFG);

    if !v4_in_pool(ipv4_dst, cfg) {
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    with_counters(|prod, debug| {
        debug.dbg_rev_pool_match = debug.dbg_rev_pool_match.saturating_add(1);
    });

    if is_fragment {
        with_counters(|prod, debug| {
            prod.unsupported_ipv4_fragments = prod.unsupported_ipv4_fragments.saturating_add(1);
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        with_counters(|prod, debug| {
            prod.unsupported_ipv4_non_tcp_udp = prod.unsupported_ipv4_non_tcp_udp.saturating_add(1);
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    if proto == IPPROTO_TCP {
        with_counters(|prod, debug| {
            prod.pkts_ipv4_tcp = prod.pkts_ipv4_tcp.saturating_add(1);
            debug.pkts_ipv4_to_v4src = debug.pkts_ipv4_to_v4src.saturating_add(1);
        });

        let tcp_len = total_len - ihl_bytes;
        if tcp_len > MAX_L4_LEN {
            with_counters(|prod, debug| {
                prod.nat64_v4_to_v6_err_csum = prod.nat64_v4_to_v6_err_csum.saturating_add(1);
            });
            with_counters(|prod, debug| {
                debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }

        let tcp_offset = l3_offset + ihl_bytes;
        let (tcp_sport, tcp_dport) = tcp_ports(&ctx, tcp_offset).map_err(|_| TC_ACT_PIPE)?;

        let lookup_key = nat_lookup_key_from_ipv4(ipv4_dst, tcp_dport, IPPROTO_TCP);
        let Some(nat_ptr) = NAT.get_ptr_mut(&lookup_key) else {
            with_counters(|prod, debug| {
                prod.nat_lookup_miss = prod.nat_lookup_miss.saturating_add(1);
                debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        };
        let mut nat_val = unsafe { *nat_ptr };
        with_counters(|prod, _| {
            prod.nat_lookup_hit = prod.nat_lookup_hit.saturating_add(1);
        });
        if !nat_tuple_matches(&nat_val, ipv4_src, tcp_sport) {
            with_counters(|prod, debug| {
                prod.nat_lookup_tuple_mismatch = prod.nat_lookup_tuple_mismatch.saturating_add(1);
                prod.nat_lookup_miss = prod.nat_lookup_miss.saturating_add(1);
                debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }
        nat_val.last_seen_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        unsafe { (*nat_ptr).last_seen_ns = nat_val.last_seen_ns };
        with_counters(|prod, _| {
            prod.nat_hit_refresh_ok = prod.nat_hit_refresh_ok.saturating_add(1);
        });

        if ctx.change_proto(ETH_P_IPV6_HELPER, 0).is_err() {
            with_counters(|prod, debug| {
                debug.nat64_v4_to_v6_err_change_proto =
                    debug.nat64_v4_to_v6_err_change_proto.saturating_add(1);
            });
            with_counters(|prod, debug| {
                debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
            });
            if should_log_change_proto_fail(false) {
                unsafe {
                    bpf_printk!(
                        c"dbg change_proto fail: target=ipv6 host=0x%x helper=0x%x",
                        ETH_P_IPV6 as u32,
                        ETH_P_IPV6_HELPER as u32
                    );
                }
            }
            return Ok(TC_ACT_PIPE);
        }

        let eth_p_ipv6 = ETH_P_IPV6.to_be_bytes();
        if ctx.store(12, &eth_p_ipv6, 0).is_err() {
            with_counters(|prod, debug| {
                debug.nat64_v4_to_v6_err_l2_store =
                    debug.nat64_v4_to_v6_err_l2_store.saturating_add(1);
            });
            with_counters(|prod, debug| {
                debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }

        let mut src_v6 = [0u8; 16];
        src_v6[..12].copy_from_slice(&NAT64_WKPF_PREFIX);
        src_v6[12..16].copy_from_slice(&ipv4_src.to_be_bytes());

        if write_ipv6_header(
            &mut ctx,
            tcp_len as u16,
            IPPROTO_TCP,
            &src_v6,
            &nat_val.vm_v6,
        )
        .is_err()
        {
            with_counters(|prod, debug| {
                prod.nat64_v4_to_v6_err_write_hdr =
                    prod.nat64_v4_to_v6_err_write_hdr.saturating_add(1);
            });
            with_counters(|prod, debug| {
                debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }

        let new_tcp_offset = ETH_HDR_LEN + 40;
        let vm_port_be = nat_val.vm_port.to_be_bytes();
        if ctx.store(new_tcp_offset + 2, &vm_port_be, 0).is_err() {
            with_counters(|prod, debug| {
                debug.rewrite_tcp_dport_err = debug.rewrite_tcp_dport_err.saturating_add(1);
            });
            with_counters(|prod, debug| {
                debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }

        with_counters(|prod, debug| {
            debug.rewrite_tcp_dport_ok = debug.rewrite_tcp_dport_ok.saturating_add(1);
        });

        // Verifier/performance note:
        // Do not recompute full TCP/UDP checksums from payload here.
        // NAT64 only changes pseudo-header fields and selected ports,
        // so use incremental checksum update helpers instead.
        if apply_l4_nat64_checksum_delta_v4_to_v6(
            &ctx,
            new_tcp_offset + 16,
            tcp_len as u16,
            IPPROTO_TCP,
            ipv4_src,
            ipv4_dst,
            &src_v6,
            &nat_val.vm_v6,
            Some((tcp_dport, nat_val.vm_port)),
            false,
        )
        .is_err()
        {
            with_counters(|prod, debug| {
                prod.nat64_v4_to_v6_err_csum = prod.nat64_v4_to_v6_err_csum.saturating_add(1);
            });
            with_counters(|prod, debug| {
                debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
            });
            return Ok(TC_ACT_PIPE);
        }

        with_counters(|prod, debug| {
            prod.nat64_v4_to_v6_ok = prod.nat64_v4_to_v6_ok.saturating_add(1);
            debug.rev_rewrite_ok_before_redirect =
                debug.rev_rewrite_ok_before_redirect.saturating_add(1);
        });
        return Ok(redirect_to_iface(cfg.bridge_ifindex, false));
    }

    with_counters(|prod, debug| {
        prod.pkts_ipv4_udp = prod.pkts_ipv4_udp.saturating_add(1);
    });

    let udp_off_v4 = ETH_HDR_LEN + ihl_bytes;
    let (udp_sport, udp_dport, udp_len) = match udp_ports_len_reverse(&ctx, udp_off_v4) {
        Ok(v) => v,
        Err(ret) => return Ok(ret),
    };

    let udp_len_usize = usize::from(udp_len);
    if udp_len_usize < UDP_HDR_LEN
        || udp_len_usize > MAX_L4_LEN
        || total_len < ihl_bytes + udp_len_usize
    {
        with_counters(|prod, debug| {
            debug.nat64_v4_to_v6_udp_err_len = debug.nat64_v4_to_v6_udp_err_len.saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let lookup_key = nat_lookup_key_from_ipv4(ipv4_dst, udp_dport, IPPROTO_UDP);
    let Some(nat_ptr) = NAT.get_ptr_mut(&lookup_key) else {
        with_counters(|prod, debug| {
            prod.nat64_v4_to_v6_udp_miss = prod.nat64_v4_to_v6_udp_miss.saturating_add(1);
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    };
    let nat_val = unsafe { *nat_ptr };

    if nat_val.remote_v4 != ipv4_src || nat_val.remote_port != udp_sport {
        with_counters(|prod, debug| {
            prod.nat64_v4_to_v6_udp_tuple_mismatch =
                prod.nat64_v4_to_v6_udp_tuple_mismatch.saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let mut refreshed = nat_val;
    refreshed.last_seen_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    unsafe { (*nat_ptr).last_seen_ns = refreshed.last_seen_ns };
    with_counters(|prod, _| {
        prod.nat_hit_refresh_ok = prod.nat_hit_refresh_ok.saturating_add(1);
    });

    if ctx.change_proto(ETH_P_IPV6_HELPER, 0).is_err() {
        with_counters(|prod, debug| {
            debug.nat64_v4_to_v6_udp_err_change_proto =
                debug.nat64_v4_to_v6_udp_err_change_proto.saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        if should_log_change_proto_fail(false) {
            unsafe {
                bpf_printk!(
                    c"dbg change_proto fail: target=ipv6 host=0x%x helper=0x%x",
                    ETH_P_IPV6 as u32,
                    ETH_P_IPV6_HELPER as u32
                );
            }
        }
        return Ok(TC_ACT_PIPE);
    }

    let eth_p_ipv6 = ETH_P_IPV6.to_be_bytes();
    if ctx.store(12, &eth_p_ipv6, 0).is_err() {
        with_counters(|prod, debug| {
            debug.nat64_v4_to_v6_udp_err_l2_store =
                debug.nat64_v4_to_v6_udp_err_l2_store.saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let mut src_v6 = [0u8; 16];
    src_v6[..12].copy_from_slice(&NAT64_WKPF_PREFIX);
    src_v6[12..16].copy_from_slice(&ipv4_src.to_be_bytes());

    if write_ipv6_header(&mut ctx, udp_len, IPPROTO_UDP, &src_v6, &refreshed.vm_v6).is_err() {
        with_counters(|prod, debug| {
            debug.nat64_v4_to_v6_udp_err_parse =
                debug.nat64_v4_to_v6_udp_err_parse.saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let udp_off_v6 = ETH_HDR_LEN + 40;
    let vm_port_be = refreshed.vm_port.to_be_bytes();
    if ctx.store(udp_off_v6 + 2, &vm_port_be, 0).is_err() {
        with_counters(|prod, debug| {
            debug.nat64_v4_to_v6_udp_err_dport_store =
                debug.nat64_v4_to_v6_udp_err_dport_store.saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    let incoming_udp_checksum = ctx.load::<u16>(udp_off_v4 + 6).map_err(|_| TC_ACT_PIPE)?;
    if incoming_udp_checksum == 0 {
        // IPv4 UDP checksum may be zero, but IPv6 UDP checksum is mandatory.
        // For now, skip translation for zero-checksum IPv4 UDP packets.
        with_counters(|prod, debug| {
            prod.unsupported_ipv4_udp_zero_checksum =
                prod.unsupported_ipv4_udp_zero_checksum.saturating_add(1);
            debug.nat64_v4_to_v6_udp_zero_csum_unsupported = debug
                .nat64_v4_to_v6_udp_zero_csum_unsupported
                .saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    // Verifier/performance note:
    // Do not recompute full TCP/UDP checksums from payload here.
    // NAT64 only changes pseudo-header fields and selected ports,
    // so use incremental checksum update helpers instead.
    if apply_l4_nat64_checksum_delta_v4_to_v6(
        &ctx,
        udp_off_v6 + 6,
        udp_len,
        IPPROTO_UDP,
        ipv4_src,
        ipv4_dst,
        &src_v6,
        &refreshed.vm_v6,
        Some((udp_dport, refreshed.vm_port)),
        true,
    )
    .is_err()
    {
        with_counters(|prod, debug| {
            debug.nat64_v4_to_v6_udp_err_csum = debug.nat64_v4_to_v6_udp_err_csum.saturating_add(1);
        });
        with_counters(|prod, debug| {
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        });
        return Ok(TC_ACT_PIPE);
    }

    with_counters(|prod, debug| {
        prod.nat64_v4_to_v6_udp_ok = prod.nat64_v4_to_v6_udp_ok.saturating_add(1);
        debug.rev_rewrite_ok_before_redirect =
            debug.rev_rewrite_ok_before_redirect.saturating_add(1);
    });

    Ok(redirect_to_iface(cfg.bridge_ifindex, false))
}

#[inline(always)]
fn redirect_to_iface(ifindex: u32, forward: bool) -> i32 {
    if ifindex == 0 {
        with_counters(|prod, debug| {
            if forward {
                prod.fwd_redirect_err = prod.fwd_redirect_err.saturating_add(1);
                debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
            } else {
                prod.rev_redirect_err = prod.rev_redirect_err.saturating_add(1);
                debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
            }
        });
        return TC_ACT_SHOT;
    }

    let action = unsafe { bpf_redirect_neigh(ifindex, core::ptr::null_mut(), 0, 0) } as i32;

    with_counters(|prod, debug| {
        if action == TC_ACT_REDIRECT {
            if forward {
                prod.fwd_redirect_ok = prod.fwd_redirect_ok.saturating_add(1);
                debug.dbg_fwd_return_ok = debug.dbg_fwd_return_ok.saturating_add(1);
            } else {
                prod.rev_redirect_ok = prod.rev_redirect_ok.saturating_add(1);
                debug.dbg_rev_return_ok = debug.dbg_rev_return_ok.saturating_add(1);
            }
        } else if forward {
            prod.fwd_redirect_err = prod.fwd_redirect_err.saturating_add(1);
            debug.dbg_fwd_return_err = debug.dbg_fwd_return_err.saturating_add(1);
        } else {
            prod.rev_redirect_err = prod.rev_redirect_err.saturating_add(1);
            debug.dbg_rev_return_err = debug.dbg_rev_return_err.saturating_add(1);
        }
    });

    if action != TC_ACT_REDIRECT {
        unsafe {
            bpf_printk!(
                c"dbg redirect_neigh unexpected action=%d ifindex=%d dir=%d",
                action as u32,
                ifindex,
                if forward { 1 } else { 0 }
            );
        }
    }

    action
}

#[inline(never)]
fn write_ipv4_header(
    ctx: &mut TcContext,
    payload_len: u16,
    src_v4: u32,
    dst_v4: u32,
    l4_proto: u8,
) -> Result<(), ()> {
    let total_len = payload_len.checked_add(IPV4_HDR_LEN as u16).ok_or(())?;

    let mut hdr = [0u8; IPV4_HDR_LEN];
    hdr[0] = 0x45;
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    hdr[8] = 64;
    hdr[9] = l4_proto;
    hdr[12..16].copy_from_slice(&src_v4.to_be_bytes());
    hdr[16..20].copy_from_slice(&dst_v4.to_be_bytes());

    let checksum = ipv4_header_checksum_20b_local(&hdr);
    hdr[10..12].copy_from_slice(&checksum.to_be_bytes());

    ctx.store(ETH_HDR_LEN, &hdr, 0).map_err(|_| ())
}

// Verifier note:
// Do not use the shared checksum fold helper in eBPF, because its carry-fold
// while-loop causes verifier complexity blowups. Keep this helper fully
// straight-line and fixed-width.
#[inline(always)]
fn fold_u32_fixed(mut sum: u32) -> u16 {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum as u16
}

#[inline(always)]
fn ipv4_header_checksum_20b_local(hdr: &[u8; 20]) -> u16 {
    let mut sum = 0u32;
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[0], hdr[1]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[2], hdr[3]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[4], hdr[5]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[6], hdr[7]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[8], hdr[9]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[10], hdr[11]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[12], hdr[13]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[14], hdr[15]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[16], hdr[17]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[18], hdr[19]])));
    !fold_u32_fixed(sum)
}

#[inline(always)]
fn tcp_ports(ctx: &TcContext, tcp_offset: usize) -> Result<(u16, u16), ()> {
    let sport_be = u16::from_be(ctx.load::<u16>(tcp_offset).map_err(|_| ())?);
    let dport_be = u16::from_be(ctx.load::<u16>(tcp_offset + 2).map_err(|_| ())?);
    Ok((sport_be, dport_be))
}

#[inline(never)]
fn udp_ports_len_reverse(ctx: &TcContext, udp_offset: usize) -> Result<(u16, u16, u16), i32> {
    let sport = match ctx.load::<u16>(udp_offset) {
        Ok(v) => u16::from_be(v),
        Err(_) => {
            with_counters(|prod, debug| {
                debug.nat64_v4_to_v6_udp_err_parse =
                    debug.nat64_v4_to_v6_udp_err_parse.saturating_add(1)
            });
            return Err(TC_ACT_PIPE);
        }
    };

    let dport = match ctx.load::<u16>(udp_offset + 2) {
        Ok(v) => u16::from_be(v),
        Err(_) => {
            with_counters(|prod, debug| {
                debug.nat64_v4_to_v6_udp_err_parse =
                    debug.nat64_v4_to_v6_udp_err_parse.saturating_add(1)
            });
            return Err(TC_ACT_PIPE);
        }
    };

    let udp_len = match ctx.load::<u16>(udp_offset + 4) {
        Ok(v) => u16::from_be(v),
        Err(_) => {
            with_counters(|prod, debug| {
                debug.nat64_v4_to_v6_udp_err_parse =
                    debug.nat64_v4_to_v6_udp_err_parse.saturating_add(1)
            });
            return Err(TC_ACT_PIPE);
        }
    };

    Ok((sport, dport, udp_len))
}

#[inline(never)]
fn udp_ports_len(ctx: &TcContext, udp_offset: usize) -> Result<(u16, u16, u16), i32> {
    let sport = match ctx.load::<u16>(udp_offset) {
        Ok(v) => u16::from_be(v),
        Err(_) => {
            with_counters(|prod, debug| {
                debug.nat64_v6_to_v4_udp_err_parse =
                    debug.nat64_v6_to_v4_udp_err_parse.saturating_add(1)
            });
            return Err(TC_ACT_PIPE);
        }
    };

    let dport = match ctx.load::<u16>(udp_offset + 2) {
        Ok(v) => u16::from_be(v),
        Err(_) => {
            with_counters(|prod, debug| {
                debug.nat64_v6_to_v4_udp_err_parse =
                    debug.nat64_v6_to_v4_udp_err_parse.saturating_add(1)
            });
            return Err(TC_ACT_PIPE);
        }
    };

    let udp_len = match ctx.load::<u16>(udp_offset + 4) {
        Ok(v) => u16::from_be(v),
        Err(_) => {
            with_counters(|prod, debug| {
                debug.nat64_v6_to_v4_udp_err_parse =
                    debug.nat64_v6_to_v4_udp_err_parse.saturating_add(1)
            });
            return Err(TC_ACT_PIPE);
        }
    };

    Ok((sport, dport, udp_len))
}

#[inline(always)]
fn csum_diff(old_bytes: &mut [u8], new_bytes: &mut [u8]) -> Result<u64, ()> {
    if !old_bytes.len().is_multiple_of(4) || !new_bytes.len().is_multiple_of(4) {
        return Err(());
    }

    let from_size = u32::try_from(old_bytes.len()).map_err(|_| ())?;
    let to_size = u32::try_from(new_bytes.len()).map_err(|_| ())?;

    let diff = unsafe {
        bpf_csum_diff(
            old_bytes.as_mut_ptr().cast(),
            from_size,
            new_bytes.as_mut_ptr().cast(),
            to_size,
            0,
        )
    };

    if diff < 0 { Err(()) } else { Ok(diff as u64) }
}

#[derive(Clone, Copy)]
struct FwdL4CsumTrace {
    old_check_be: u16,
    after_pseudo_be: u16,
    after_port_be: u16,
}

#[inline(always)]
fn apply_l4_nat64_checksum_delta_v6_to_v4(
    ctx: &TcContext,
    csum_offset: usize,
    l4_len: u16,
    proto: u8,
    old_src_v6: &[u8; 16],
    old_dst_v6: &[u8; 16],
    new_src_v4: u32,
    new_dst_v4: u32,
    port_rewrite: Option<(u16, u16)>,
    udp_ipv4: bool,
) -> Result<FwdL4CsumTrace, ()> {
    let old_check_be = ctx.load::<u16>(csum_offset).map_err(|_| ())?;

    let mut old_pseudo = build_ipv6_pseudo_header_bytes(old_src_v6, old_dst_v6, l4_len, proto);
    let mut new_pseudo = build_ipv4_pseudo_header_bytes(new_src_v4, new_dst_v4, l4_len, proto);
    let pseudo_delta = csum_diff(&mut old_pseudo, &mut new_pseudo)?;

    ctx.l4_csum_replace(csum_offset, 0, pseudo_delta, u64::from(BPF_F_PSEUDO_HDR))
        .map_err(|_| {
            with_counters(|prod, debug| {
                debug.dbg_fwd_l4_csum_pseudo_err =
                    debug.dbg_fwd_l4_csum_pseudo_err.saturating_add(1)
            });
        })?;

    let after_pseudo_be = ctx.load::<u16>(csum_offset).map_err(|_| ())?;

    if let Some((old_port, new_port)) = port_rewrite {
        ctx.l4_csum_replace(
            csum_offset,
            u64::from(old_port.to_be()),
            u64::from(new_port.to_be()),
            2,
        )
        .map_err(|_| {
            with_counters(|prod, debug| {
                debug.dbg_fwd_l4_csum_port_err = debug.dbg_fwd_l4_csum_port_err.saturating_add(1)
            });
        })?;
    }

    let after_port_be = ctx.load::<u16>(csum_offset).map_err(|_| ())?;

    if udp_ipv4 {
        let zero = u16::to_be(0u16);
        let ffff = u16::to_be(0xffffu16);
        let flags = 2u64 | u64::from(BPF_F_MARK_MANGLED_0);
        ctx.l4_csum_replace(csum_offset, u64::from(zero), u64::from(ffff), flags)
            .map_err(|_| ())?;
    }

    Ok(FwdL4CsumTrace {
        old_check_be,
        after_pseudo_be,
        after_port_be,
    })
}

#[inline(always)]
fn apply_l4_nat64_checksum_delta_v4_to_v6(
    ctx: &TcContext,
    csum_offset: usize,
    l4_len: u16,
    proto: u8,
    old_src_v4: u32,
    old_dst_v4: u32,
    new_src_v6: &[u8; 16],
    new_dst_v6: &[u8; 16],
    port_rewrite: Option<(u16, u16)>,
    udp_v6: bool,
) -> Result<(), ()> {
    let mut old_pseudo = build_ipv4_pseudo_header_bytes(old_src_v4, old_dst_v4, l4_len, proto);
    let mut new_pseudo = build_ipv6_pseudo_header_bytes(new_src_v6, new_dst_v6, l4_len, proto);
    let pseudo_delta = csum_diff(&mut old_pseudo, &mut new_pseudo)?;

    ctx.l4_csum_replace(csum_offset, 0, pseudo_delta, u64::from(BPF_F_PSEUDO_HDR))
        .map_err(|_| ())?;

    if let Some((old_port, new_port)) = port_rewrite {
        ctx.l4_csum_replace(
            csum_offset,
            u64::from(old_port.to_be()),
            u64::from(new_port.to_be()),
            2,
        )
        .map_err(|_| ())?;
    }

    if udp_v6 {
        let flags = 2u64 | u64::from(BPF_F_PSEUDO_HDR) | u64::from(BPF_F_MARK_MANGLED_0);
        ctx.l4_csum_replace(csum_offset, 0, 0, flags)
            .map_err(|_| ())?;
    }

    Ok(())
}

#[inline(always)]
fn select_v4_from_pool_ebpf(vm_v6: &[u8; 16], cfg: &Nat64Config) -> Option<u32> {
    let len = cfg.v4_pool_len;
    if len == 0 || len > V4_POOL_MAX as u32 {
        return None;
    }

    let mut hash = 0x811c_9dc5u32;
    for byte in vm_v6 {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }

    let idx = hash % len;

    // Verifier requirement: avoid dynamic indexing into map-value arrays.
    // Load fixed offsets first, then select with match.
    let v0 = cfg.v4_pool[0];
    let v1 = cfg.v4_pool[1];
    let v2 = cfg.v4_pool[2];
    let v3 = cfg.v4_pool[3];
    let v4 = cfg.v4_pool[4];
    let v5 = cfg.v4_pool[5];
    let v6 = cfg.v4_pool[6];
    let v7 = cfg.v4_pool[7];
    let v8 = cfg.v4_pool[8];
    let v9 = cfg.v4_pool[9];
    let v10 = cfg.v4_pool[10];
    let v11 = cfg.v4_pool[11];
    let v12 = cfg.v4_pool[12];
    let v13 = cfg.v4_pool[13];
    let v14 = cfg.v4_pool[14];
    let v15 = cfg.v4_pool[15];

    let out = match idx {
        0 => v0,
        1 => v1,
        2 => v2,
        3 => v3,
        4 => v4,
        5 => v5,
        6 => v6,
        7 => v7,
        8 => v8,
        9 => v9,
        10 => v10,
        11 => v11,
        12 => v12,
        13 => v13,
        14 => v14,
        15 => v15,
        _ => return None,
    };

    Some(out)
}

#[inline(always)]
fn v4_in_pool(v4: u32, cfg: &Nat64Config) -> bool {
    let len = cfg.v4_pool_len;
    if len == 0 || len > V4_POOL_MAX as u32 {
        return false;
    }

    let p0 = cfg.v4_pool[0];
    let p1 = cfg.v4_pool[1];
    let p2 = cfg.v4_pool[2];
    let p3 = cfg.v4_pool[3];
    let p4 = cfg.v4_pool[4];
    let p5 = cfg.v4_pool[5];
    let p6 = cfg.v4_pool[6];
    let p7 = cfg.v4_pool[7];
    let p8 = cfg.v4_pool[8];
    let p9 = cfg.v4_pool[9];
    let p10 = cfg.v4_pool[10];
    let p11 = cfg.v4_pool[11];
    let p12 = cfg.v4_pool[12];
    let p13 = cfg.v4_pool[13];
    let p14 = cfg.v4_pool[14];
    let p15 = cfg.v4_pool[15];

    match len {
        1 => v4 == p0,
        2 => v4 == p0 || v4 == p1,
        3 => v4 == p0 || v4 == p1 || v4 == p2,
        4 => v4 == p0 || v4 == p1 || v4 == p2 || v4 == p3,
        5 => v4 == p0 || v4 == p1 || v4 == p2 || v4 == p3 || v4 == p4,
        6 => v4 == p0 || v4 == p1 || v4 == p2 || v4 == p3 || v4 == p4 || v4 == p5,
        7 => v4 == p0 || v4 == p1 || v4 == p2 || v4 == p3 || v4 == p4 || v4 == p5 || v4 == p6,
        8 => {
            v4 == p0
                || v4 == p1
                || v4 == p2
                || v4 == p3
                || v4 == p4
                || v4 == p5
                || v4 == p6
                || v4 == p7
        }
        9 => {
            v4 == p0
                || v4 == p1
                || v4 == p2
                || v4 == p3
                || v4 == p4
                || v4 == p5
                || v4 == p6
                || v4 == p7
                || v4 == p8
        }
        10 => {
            v4 == p0
                || v4 == p1
                || v4 == p2
                || v4 == p3
                || v4 == p4
                || v4 == p5
                || v4 == p6
                || v4 == p7
                || v4 == p8
                || v4 == p9
        }
        11 => {
            v4 == p0
                || v4 == p1
                || v4 == p2
                || v4 == p3
                || v4 == p4
                || v4 == p5
                || v4 == p6
                || v4 == p7
                || v4 == p8
                || v4 == p9
                || v4 == p10
        }
        12 => {
            v4 == p0
                || v4 == p1
                || v4 == p2
                || v4 == p3
                || v4 == p4
                || v4 == p5
                || v4 == p6
                || v4 == p7
                || v4 == p8
                || v4 == p9
                || v4 == p10
                || v4 == p11
        }
        13 => {
            v4 == p0
                || v4 == p1
                || v4 == p2
                || v4 == p3
                || v4 == p4
                || v4 == p5
                || v4 == p6
                || v4 == p7
                || v4 == p8
                || v4 == p9
                || v4 == p10
                || v4 == p11
                || v4 == p12
        }
        14 => {
            v4 == p0
                || v4 == p1
                || v4 == p2
                || v4 == p3
                || v4 == p4
                || v4 == p5
                || v4 == p6
                || v4 == p7
                || v4 == p8
                || v4 == p9
                || v4 == p10
                || v4 == p11
                || v4 == p12
                || v4 == p13
        }
        15 => {
            v4 == p0
                || v4 == p1
                || v4 == p2
                || v4 == p3
                || v4 == p4
                || v4 == p5
                || v4 == p6
                || v4 == p7
                || v4 == p8
                || v4 == p9
                || v4 == p10
                || v4 == p11
                || v4 == p12
                || v4 == p13
                || v4 == p14
        }
        16 => {
            v4 == p0
                || v4 == p1
                || v4 == p2
                || v4 == p3
                || v4 == p4
                || v4 == p5
                || v4 == p6
                || v4 == p7
                || v4 == p8
                || v4 == p9
                || v4 == p10
                || v4 == p11
                || v4 == p12
                || v4 == p13
                || v4 == p14
                || v4 == p15
        }
        _ => false,
    }
}

#[inline(never)]
fn cooldown_contains(ring: &PortCooldownRing, port: u16) -> bool {
    for i in 0..COOLDOWN_SIZE {
        if ring.ports[i] == port {
            return true;
        }
    }
    false
}

#[inline(never)]
fn cooldown_push(ring: &mut PortCooldownRing, port: u16) {
    let slot = (ring.idx as usize) % COOLDOWN_SIZE;
    ring.ports[slot] = port;
    ring.idx = ring.idx.wrapping_add(1);
}

#[inline(always)]
fn alloc_port(cfg: &Nat64Config, ext_v4: u32, proto: u8) -> Option<u16> {
    if cfg.port_min >= cfg.port_max {
        return None;
    }

    let span = u32::from(cfg.port_max - cfg.port_min) + 1;
    let cursor_ptr = PORT_CURSOR.get_ptr_mut(0)?;
    let cooldown_ptr = PORT_COOLDOWN.get_ptr_mut(0);
    let mut cursor = unsafe { *cursor_ptr };
    let mut had_cooldown_skip = false;

    for _ in 0..16 {
        with_counters(|prod, debug| {
            debug.port_alloc_probe = debug.port_alloc_probe.saturating_add(1);
        });

        cursor = cursor.wrapping_add(1);
        let candidate = u32::from(cfg.port_min) + (cursor % span);
        unsafe {
            *cursor_ptr = cursor;
        }

        let Ok(port) = u16::try_from(candidate) else {
            continue;
        };

        if let Some(ring_ptr) = cooldown_ptr {
            let ring = unsafe { &*ring_ptr };
            if cooldown_contains(ring, port) {
                with_counters(|prod, debug| {
                    debug.cooldown_skip = debug.cooldown_skip.saturating_add(1);
                });
                had_cooldown_skip = true;
                continue;
            }
        }

        let key = nat_key(ext_v4, port, proto);
        if unsafe { NAT.get(&key) }.is_some() {
            with_counters(|prod, debug| {
                debug.port_alloc_collide = debug.port_alloc_collide.saturating_add(1);
            });
            continue;
        }

        if had_cooldown_skip {
            with_counters(|prod, debug| {
                debug.cooldown_probe_more = debug.cooldown_probe_more.saturating_add(1);
            });
        }

        if let Some(ring_ptr) = cooldown_ptr {
            let ring = unsafe { &mut *ring_ptr };
            cooldown_push(ring, port);
            with_counters(|prod, debug| {
                debug.cooldown_push_ok = debug.cooldown_push_ok.saturating_add(1);
            });
        } else {
            with_counters(|prod, debug| {
                debug.cooldown_push_err = debug.cooldown_push_err.saturating_add(1);
            });
        }

        return Some(port);
    }

    unsafe {
        *cursor_ptr = cursor;
    }
    with_counters(|prod, debug| {
        prod.port_alloc_exhausted = prod.port_alloc_exhausted.saturating_add(1);
    });
    None
}

#[inline(always)]
fn record_fwd_tcp_csum_sample(
    trace: FwdL4CsumTrace,
    final_check_be: u16,
    old_sport_be: u16,
    new_sport_be: u16,
    src_v4: u32,
    dst_v4: u32,
) -> Result<(), ()> {
    with_counters(|prod, debug| {
        debug.dbg_fwd_tcp_csum_sample_attempt =
            debug.dbg_fwd_tcp_csum_sample_attempt.saturating_add(1);
    });

    let Some(cursor_ref) = DBG_FWD_TCP_CSUM_SAMPLE_CURSOR.get_ptr_mut(0) else {
        with_counters(|prod, debug| {
            debug.dbg_fwd_tcp_csum_sample_err = debug.dbg_fwd_tcp_csum_sample_err.saturating_add(1);
        });
        return Err(());
    };

    let seq = unsafe {
        let current = *cursor_ref;
        *cursor_ref = current.wrapping_add(1);
        current.wrapping_add(1)
    };

    let idx = seq % DBG_FWD_TCP_CSUM_SAMPLE_SLOTS;
    let Some(slot_ref) = DBG_FWD_TCP_CSUM_SAMPLES.get_ptr_mut(idx) else {
        with_counters(|prod, debug| {
            debug.dbg_fwd_tcp_csum_sample_err = debug.dbg_fwd_tcp_csum_sample_err.saturating_add(1);
        });
        return Err(());
    };

    unsafe {
        *slot_ref = DbgFwdTcpCsumSample {
            seq: u64::from(seq),
            old_check_be: trace.old_check_be,
            after_pseudo_be: trace.after_pseudo_be,
            after_port_be: trace.after_port_be,
            final_check_be,
            old_sport_be,
            new_sport_be,
            _pad: 0,
            src_v4,
            dst_v4,
        };
    }

    with_counters(|prod, debug| {
        debug.dbg_fwd_tcp_csum_sample_ok = debug.dbg_fwd_tcp_csum_sample_ok.saturating_add(1);
    });

    if seq == 1 {
        unsafe {
            bpf_printk!(
                c"dbg csum sample write: old=0x%x pseudo=0x%x port=0x%x final=0x%x sport_old=%u sport_new=%u",
                u32::from(u16::from_be(trace.old_check_be)),
                u32::from(u16::from_be(trace.after_pseudo_be)),
                u32::from(u16::from_be(trace.after_port_be)),
                u32::from(u16::from_be(final_check_be)),
                u32::from(u16::from_be(old_sport_be)),
                u32::from(u16::from_be(new_sport_be)),
            );
        }
    }

    Ok(())
}

#[inline(always)]

fn record_fwd_tcp_sample(
    dst6: &[u8; 16],
    dst4: [u8; 4],
    dst4_be: u32,
    src4_be: u32,
    tcp_sport: u16,
    tcp_dport: u16,
    nat_insert_ok: bool,
    adjust_room_ok: bool,
) {
    let cursor_ref = DBG_FWD_TCP_SAMPLE_CURSOR.get_ptr_mut(0);
    let Some(cursor_ref) = cursor_ref else {
        return;
    };

    let seq = unsafe {
        let current = *cursor_ref;
        *cursor_ref = current.wrapping_add(1);
        current.wrapping_add(1)
    };

    let idx = seq % DBG_FWD_TCP_SAMPLE_SLOTS;
    let slot_ref = DBG_FWD_TCP_SAMPLES.get_ptr_mut(idx);
    let Some(slot_ref) = slot_ref else {
        return;
    };

    unsafe {
        *slot_ref = DbgFwdTcpSample {
            seq: u64::from(seq),
            dst6: *dst6,
            dst4,
            dst4_be,
            src4_be,
            tcp_sport,
            tcp_dport,
            nat_insert_ok: nat_insert_ok as u8,
            adjust_room_ok: adjust_room_ok as u8,
            _pad: [0; 6],
        };
    }
}
fn record_fwd_dst_sample(dst: &[u8; 16]) {
    let Some(cursor_ptr) = DBG_FWD_DST_SAMPLE_CURSOR.get_ptr_mut(0) else {
        return;
    };

    let cursor = unsafe { *cursor_ptr };
    let idx = cursor % DBG_FWD_DST_SAMPLE_SLOTS;

    if let Some(sample_ptr) = DBG_FWD_DST_SAMPLES.get_ptr_mut(idx) {
        unsafe {
            (*sample_ptr).seq = u64::from(cursor).saturating_add(1);
            (*sample_ptr).dst = *dst;
        }
    }

    unsafe {
        *cursor_ptr = cursor.wrapping_add(1);
    }
}

#[inline(always)]
fn classify_fwd_dst(dst: &[u8; 16]) {
    if dst[..12] == NAT64_WKPF_PREFIX {
        with_counters(|prod, debug| {
            debug.dbg_fwd_dst_nat64_prefix = debug.dbg_fwd_dst_nat64_prefix.saturating_add(1);
        });
        return;
    }

    if dst[0] == 0xff {
        with_counters(|prod, debug| {
            debug.dbg_fwd_dst_multicast = debug.dbg_fwd_dst_multicast.saturating_add(1);
        });
        return;
    }

    if dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80 {
        with_counters(|prod, debug| {
            debug.dbg_fwd_dst_link_local = debug.dbg_fwd_dst_link_local.saturating_add(1);
        });
        return;
    }

    if (dst[0] & 0xe0) == 0x20 {
        with_counters(|prod, debug| {
            debug.dbg_fwd_dst_global_non_nat64 =
                debug.dbg_fwd_dst_global_non_nat64.saturating_add(1);
        });
        return;
    }

    with_counters(|prod, debug| {
        debug.dbg_fwd_dst_other = debug.dbg_fwd_dst_other.saturating_add(1);
    });
}

#[inline(always)]
fn with_prod_counters<F>(f: F)
where
    F: FnOnce(&mut ProdCounters),
{
    if let Some(counters) = PROD_COUNTERS.get_ptr_mut(0) {
        unsafe {
            f(&mut *counters);
        }
    }
}

#[inline(always)]
fn with_debug_counters<F>(f: F)
where
    F: FnOnce(&mut DebugCounters),
{
    if let Some(counters) = DEBUG_COUNTERS.get_ptr_mut(0) {
        unsafe {
            f(&mut *counters);
        }
    }
}

#[inline(always)]
fn with_counters<F>(f: F)
where
    F: FnOnce(&mut ProdCounters, &mut DebugCounters),
{
    with_prod_counters(|prod| with_debug_counters(|debug| f(prod, debug)));
}

#[inline(always)]
fn should_log_change_proto_fail(is_forward: bool) -> bool {
    let map = if is_forward {
        &DBG_CHANGE_PROTO_FAIL_PRINT_FWD
    } else {
        &DBG_CHANGE_PROTO_FAIL_PRINT_REV
    };

    if let Some(slot) = map.get_ptr_mut(0) {
        unsafe {
            let seen = *slot;
            *slot = seen.saturating_add(1);
            seen < 3
        }
    } else {
        false
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[inline(never)]
fn write_ipv6_header(
    ctx: &mut TcContext,
    payload_len: u16,
    next_header: u8,
    src_v6: &[u8; 16],
    dst_v6: &[u8; 16],
) -> Result<(), ()> {
    let mut hdr = [0u8; 40];
    hdr[0] = 0x60;
    hdr[4..6].copy_from_slice(&payload_len.to_be_bytes());
    hdr[6] = next_header;
    hdr[7] = 64;
    hdr[8..24].copy_from_slice(src_v6);
    hdr[24..40].copy_from_slice(dst_v6);

    ctx.store(ETH_HDR_LEN, &hdr, 0).map_err(|_| ())
}
