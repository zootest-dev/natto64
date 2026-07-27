# opentelemetry-metrics

A minimal NAT64 application that exports production counters to the console with OpenTelemetry every 60 seconds

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
sudo cargo run -p natto64-opentelemetry-example -- \
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

## Grafana dashboard

[`grafana-dashboard.json`](grafana-dashboard.json) is ready to import into Grafana after the OpenTelemetry metrics have reached Grafana Mimir. The dashboard does not configure or change this example's exporter.

To import it:

1. Open **Dashboards → New → Import** in Grafana.
2. Upload `grafana-dashboard.json`.
3. Select the Grafana data source connected to Mimir.
4. Import the dashboard and select the desired job or instance.

The dashboard uses rates for the cumulative NAT64 counters and includes traffic, translation throughput, unsupported packets, NAT-state activity, port allocation, redirects, and translation errors.

The dashboard targets Mimir's default OTLP metric-name translation.
