use natto64::builder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let [ebpf_object, bridge, uplink, external_ipv4]: [String; 4] = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .expect("usage: natto64-example <EBPF_OBJECT> <BRIDGE> <UPLINK> <EXTERNAL_IPV4>");

    let nat64 = builder(ebpf_object)
        .with_v4_pool(vec![external_ipv4.parse()?])
        .attach(&bridge, &uplink)?;

    println!("NAT64 started on {bridge} and {uplink}. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await?;

    drop(nat64);
    Ok(())
}
