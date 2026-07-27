# simple

A minimal NAT64 application

## Quick start

Build the eBPF program

```bash
cargo +nightly -Z build-std=core build \
  -p natto64-ebpf \
  --target bpfel-unknown-none \
  --release
```

Run the example as root

```bash
sudo cargo run -p natto64-example -- \
  target/bpfel-unknown-none/release/libnatto64_ebpf.so \
  br \
  eth0 \
  203.0.113.10
```

The arguments are:

1. Path to the compiled eBPF object
2. IPv6 client-side bridge or interface
3. IPv4-facing uplink interface
4. External IPv4 address used for translated connections
