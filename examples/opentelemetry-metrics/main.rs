mod metrics;

use std::time::Duration;

use natto64::builder;
use opentelemetry::metrics::MeterProvider;
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};
use opentelemetry_stdout::MetricExporter;
use tokio::{sync::watch, time::MissedTickBehavior};

use crate::metrics::DESCRIPTORS;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let [ebpf_object, bridge, uplink, external_ipv4]: [String; 4] = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .expect(
            "usage: natto64-opentelemetry-example <EBPF_OBJECT> <BRIDGE> <UPLINK> <EXTERNAL_IPV4>",
        );

    let nat64 = builder(ebpf_object)
        .with_v4_pool(vec![external_ipv4.parse()?])
        .attach(&bridge, &uplink)?;

    let (metrics_tx, metrics_rx) = watch::channel(nat64.read_metrics()?);

    let metric_exporter = MetricExporter::default();
    let reader = PeriodicReader::builder(metric_exporter)
        .with_interval(Duration::from_secs(60))
        .build();
    let resource = Resource::builder()
        .with_service_name("natto64-opentelemetry-example")
        .build();
    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();
    let meter = provider.meter("nat64");

    let mut _instruments = Vec::new();

    for descriptor in DESCRIPTORS {
        let metrics_rx = metrics_rx.clone();

        let instrument = meter
            .u64_observable_counter(descriptor.name)
            .with_description(descriptor.description)
            .with_unit("1")
            .with_callback(move |observer| {
                let metrics = *metrics_rx.borrow();
                observer.observe((descriptor.value)(&metrics), &[]);
            })
            .build();

        _instruments.push(instrument);
    }

    let mut poll = tokio::time::interval(Duration::from_secs(5));
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

    println!("NAT64 started on {bridge} and {uplink}. Press Ctrl+C to stop.");

    loop {
        tokio::select! {
            _ = poll.tick() => match nat64.read_metrics() {
                Ok(metrics) => {
                    metrics_tx.send_replace(metrics);
                }
                Err(err) => eprintln!("failed to read NAT64 production metrics: {err}"),
            },
            signal = tokio::signal::ctrl_c() => {
                signal?;
                break;
            }
        }
    }

    metrics_tx.send_replace(nat64.read_metrics()?);
    provider.shutdown()?;

    Ok(())
}
