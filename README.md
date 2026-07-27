# natto64

[![CI](https://github.com/zootest-dev/natto64/actions/workflows/ci.yaml/badge.svg)](https://github.com/zootest-dev/natto64/actions/workflows/ci.yaml)

A NAT64 eBPF network traffic translator that lets IPv6 clients connect to IPv4 servers 🫘✨🥣

![natto64 traffic flow](natto64.png?raw=true)

## Example

```rust
use std::net::Ipv4Addr;

let nat64 = natto64::builder("libnatto64_ebpf.so")
    .with_v4_pool(vec![Ipv4Addr::new(203, 0, 113, 10)])
    .with_session_timeouts(Some(std::time::Duration::from_secs(300)))
    .attach("br", "eth0")?;
```

The standard prefix and port range can be overridden when required

```rust
let nat64 = natto64::builder("libnatto64_ebpf.so")
    .with_v4_pool(vec!["203.0.113.10".parse()?])
    .with_prefix96([0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    .with_port_min(30_000)
    .with_port_max(40_000)
    .attach("br", "eth0")?;
```

A builder can be reused. Each call to `Nat64Builder::attach` loads an independent eBPF instance with its own maps and metric counters.

```rust
let builder = natto64::builder("libnatto64_ebpf.so")
    .with_v4_pool(vec!["203.0.113.10".parse()?]);

let nat64_first = builder.attach("br-1", "eth0")?;
let nat64_second = builder.attach("br-2", "eth1")?;
```

`Nat64` should be kept alive for as long as traffic translation should remain active.

## Features

- Translation of TCP and UDP network traffic
- Stateful, bidirectional connectivity between IPv6 and IPv4
- Configurable NAT64 prefix, external IPv4 address pool, port range, and session timeout
- Per-session kernel BPF timers with no userspace map scanner
- Built-in production metric counters

### Supported traffic

NAT64 is a translator for TCP and UDP network traffic. Packets that cannot be translated are passed through unchanged. Use a firewall such as nftables when unsupported traffic addressed to the NAT64 prefix or IPv4 pool should be dropped.

- IPv4 fragments are not translated
- IPv4 UDP packets with a zero checksum cannot be translated to IPv6
- IPv6 extension-header chains are not translated

### Requirements

Session expiration uses kernel BPF timers and requires Linux 6.12 or newer

## License

GPL-2.0

![natto64 bowl](bowl.png?raw=true)
