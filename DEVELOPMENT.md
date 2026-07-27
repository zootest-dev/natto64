# development

## Requirements

- Linux with eBPF and `tc` support
- `bpf-linker`
- Root privileges when loading and attaching the eBPF programs

Install the required Rust tooling:

```bash
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo +nightly install bpf-linker --locked
```
