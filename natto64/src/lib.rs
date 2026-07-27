#![deny(missing_docs)]
//! A NAT64 eBPF network traffic translator that lets IPv6 clients connect to IPv4 servers 🫘✨🥣
//!
//! # Example
//!
//! ```no_run
//! use std::{net::Ipv4Addr, time::Duration};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let nat64 = natto64::builder("libnatto64_ebpf.so")
//!     .with_v4_pool(vec![Ipv4Addr::new(203, 0, 113, 10)])
//!     .with_session_timeouts(Some(Duration::from_secs(300)))
//!     .attach("br", "eth0")?;
//! # drop(nat64);
//! # Ok(())
//! # }
//! ```
//!

mod builder;
mod error;
mod metrics;

pub use builder::{Nat64Builder, builder};
pub use error::{Error, Result};
pub use metrics::Nat64Metrics;

use std::{fs, net::Ipv4Addr, path::Path, time::Duration};

use aya::{
    Ebpf,
    maps::{HashMap, PerCpuArray},
    programs::{SchedClassifier, TcAttachType, tc, tc::TcError},
};
use natto64_abi::{
    CONFIG_KEY, Nat64Config as DataplaneConfig, ProdCounters, V4_POOL_MAX,
    V4_SELECT_POLICY_HASH_VM_V6,
};

const CONFIG_MAP_NAME: &str = "CONFIG";
const PROD_COUNTERS_MAP_NAME: &str = "PROD_COUNTERS";
const PROD_COUNTERS_KEY: u32 = 0;
const FORWARD_PROGRAM_NAME: &str = "nat64_forward";
const REVERSE_PROGRAM_NAME: &str = "nat64_reverse";

/// The RFC 6052 well-known NAT64 `/96` prefix (`64:ff9b::/96`) in network byte order.
pub const RFC_6052_WELL_KNOWN_PREFIX: [u8; 12] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

/// User-facing NAT64 translation policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nat64Config {
    /// The first 12 bytes of the `/96` IPv6 prefix handled by NAT64.
    pub prefix96: [u8; 12],
    /// External IPv4 source addresses available to translated connections.
    pub v4_pool: Vec<Ipv4Addr>,
    /// Lowest external TCP or UDP source port available to the allocator, inclusive.
    pub port_min: u16,
    /// Highest external TCP or UDP source port available to the allocator, inclusive.
    pub port_max: u16,
    /// Idle session timeout. `None` disables expiration.
    pub session_timeout: Option<Duration>,
}

impl Nat64Config {
    fn validate(&self) -> Result<()> {
        if self.v4_pool.is_empty() {
            return Err(Error::EmptyV4Pool);
        }
        if self.v4_pool.len() > V4_POOL_MAX {
            return Err(Error::V4PoolTooLarge {
                actual: self.v4_pool.len(),
                maximum: V4_POOL_MAX,
            });
        }
        if self.port_min == 0 || self.port_min > self.port_max {
            return Err(Error::InvalidPortRange {
                port_min: self.port_min,
                port_max: self.port_max,
            });
        }
        if self
            .session_timeout
            .is_some_and(|timeout| timeout.is_zero())
        {
            return Err(Error::InvalidSessionTimeout);
        }
        Ok(())
    }

    fn dataplane_config(&self, bridge_ifindex: u32, uplink_ifindex: u32) -> DataplaneConfig {
        let mut v4_pool = [0; V4_POOL_MAX];
        for (slot, address) in v4_pool.iter_mut().zip(&self.v4_pool) {
            *slot = address.to_bits();
        }

        let session_timeout_secs = self
            .session_timeout
            .map(|timeout| {
                let rounded_up = timeout
                    .as_secs()
                    .saturating_add(u64::from(timeout.subsec_nanos() != 0));
                rounded_up.min(u64::from(u32::MAX)) as u32
            })
            .unwrap_or(0);

        DataplaneConfig {
            prefix96: self.prefix96,
            v4_pool,
            v4_pool_len: self.v4_pool.len() as u32,
            bridge_ifindex,
            uplink_ifindex,
            port_min: self.port_min,
            port_max: self.port_max,
            session_timeout_secs,
            v4_policy: V4_SELECT_POLICY_HASH_VM_V6,
            _pad: [0; 3],
        }
    }
}

/// A loaded NAT64 dataplane.
///
/// Keep this value alive while translation should remain active. Dropping it
/// releases the loaded eBPF resources and their kernel timers.
pub struct Nat64 {
    ebpf: Ebpf,
    config: Option<Nat64Config>,
    attached: bool,
}

impl Nat64 {
    /// Loads an eBPF object from `path` without configuring or attaching it.
    ///
    /// # Errors
    ///
    /// Returns an error when the object cannot be read or loaded by Aya.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let object = fs::read(path).map_err(|source| Error::ReadEbpfObject {
            path: path.to_path_buf(),
            source,
        })?;
        let ebpf = Ebpf::load(&object).map_err(|source| Error::LoadEbpfObject { source })?;

        Ok(Self {
            ebpf,
            config: None,
            attached: false,
        })
    }

    /// Validates and stores the translation policy used by [`Self::attach`].
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid policy or an already attached dataplane.
    pub fn configure(&mut self, config: Nat64Config) -> Result<()> {
        if self.attached {
            return Err(Error::AlreadyAttached);
        }
        config.validate()?;
        self.config = Some(config);
        Ok(())
    }

    /// Attaches the forward classifier to `bridge` and the reverse classifier to `uplink`.
    ///
    /// Session expiration, when configured, is owned by kernel BPF timers.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration, interface discovery, map setup,
    /// traffic control, or program attachment fails.
    pub fn attach(&mut self, bridge: &str, uplink: &str) -> Result<()> {
        if self.attached {
            return Err(Error::AlreadyAttached);
        }

        let config = self.config.as_ref().ok_or(Error::NotConfigured)?.clone();
        let bridge_ifindex = interface_index(bridge)?;
        let uplink_ifindex = interface_index(uplink)?;
        let dataplane_config = config.dataplane_config(bridge_ifindex, uplink_ifindex);
        {
            let map = self
                .ebpf
                .map_mut(CONFIG_MAP_NAME)
                .ok_or(Error::MissingMap {
                    name: CONFIG_MAP_NAME,
                })?;
            let mut map = HashMap::<_, u32, DataplaneConfig>::try_from(map)
                .map_err(|source| Error::ConfigureMap { source })?;
            map.insert(CONFIG_KEY, dataplane_config, 0)
                .map_err(|source| Error::ConfigureMap { source })?;
        }

        ensure_clsact(bridge)?;
        ensure_clsact(uplink)?;
        attach_classifier(&mut self.ebpf, FORWARD_PROGRAM_NAME, bridge)?;
        attach_classifier(&mut self.ebpf, REVERSE_PROGRAM_NAME, uplink)?;

        self.attached = true;
        Ok(())
    }

    /// Reads a cumulative production-counter snapshot for this dataplane.
    ///
    /// # Errors
    ///
    /// Returns an error when the counter map is missing or cannot be read.
    pub fn read_metrics(&self) -> Result<Nat64Metrics> {
        let map = self
            .ebpf
            .map(PROD_COUNTERS_MAP_NAME)
            .ok_or(Error::MissingMap {
                name: PROD_COUNTERS_MAP_NAME,
            })?;
        let map = PerCpuArray::<_, ProdCounters>::try_from(map)
            .map_err(|source| Error::ReadMetrics { source })?;
        let values = map
            .get(&PROD_COUNTERS_KEY, 0)
            .map_err(|source| Error::ReadMetrics { source })?;
        Ok(metrics::aggregate_prod_counters(values.iter()))
    }
}

fn ensure_clsact(interface: &str) -> Result<()> {
    match tc::qdisc_add_clsact(interface) {
        Ok(()) | Err(TcError::AlreadyAttached) => Ok(()),
        Err(source) => Err(Error::TrafficControl {
            interface: interface.to_owned(),
            source,
        }),
    }
}

fn attach_classifier(ebpf: &mut Ebpf, name: &'static str, interface: &str) -> Result<()> {
    let program = ebpf
        .program_mut(name)
        .ok_or(Error::MissingProgram { name })?;
    let classifier: &mut SchedClassifier = program
        .try_into()
        .map_err(|source| Error::Program { source })?;
    classifier
        .load()
        .map_err(|source| Error::Program { source })?;
    classifier
        .attach(interface, TcAttachType::Ingress)
        .map_err(|source| Error::Program { source })?;
    Ok(())
}

fn interface_index(interface: &str) -> Result<u32> {
    if interface.is_empty() || interface.contains('/') || interface == "." || interface == ".." {
        return Err(Error::InvalidInterfaceName {
            interface: interface.to_owned(),
        });
    }

    let path = Path::new("/sys/class/net").join(interface).join("ifindex");
    let value = fs::read_to_string(path).map_err(|source| Error::ReadInterfaceIndex {
        interface: interface.to_owned(),
        source,
    })?;
    value
        .trim()
        .parse()
        .map_err(|source| Error::ParseInterfaceIndex {
            interface: interface.to_owned(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Nat64Config {
        Nat64Config {
            prefix96: RFC_6052_WELL_KNOWN_PREFIX,
            v4_pool: vec![Ipv4Addr::new(203, 0, 113, 10)],
            port_min: 20_000,
            port_max: 60_000,
            session_timeout: None,
        }
    }

    #[test]
    fn accepts_valid_configuration() {
        assert!(config().validate().is_ok());
    }

    #[test]
    fn rejects_empty_ipv4_pool() {
        let mut config = config();
        config.v4_pool.clear();
        assert!(matches!(config.validate(), Err(Error::EmptyV4Pool)));
    }

    #[test]
    fn rejects_oversized_ipv4_pool() {
        let mut config = config();
        config.v4_pool = vec![Ipv4Addr::LOCALHOST; V4_POOL_MAX + 1];
        assert!(matches!(
            config.validate(),
            Err(Error::V4PoolTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_zero_or_reversed_port_ranges() {
        let mut zero = config();
        zero.port_min = 0;
        assert!(matches!(
            zero.validate(),
            Err(Error::InvalidPortRange { .. })
        ));

        let mut reversed = config();
        reversed.port_min = 60_000;
        reversed.port_max = 20_000;
        assert!(matches!(
            reversed.validate(),
            Err(Error::InvalidPortRange { .. })
        ));
    }

    #[test]
    fn rejects_zero_session_timeout() {
        let mut value = config();
        value.session_timeout = Some(Duration::ZERO);
        assert!(matches!(
            value.validate(),
            Err(Error::InvalidSessionTimeout)
        ));
    }

    #[test]
    fn rounds_session_timeout_up_for_the_dataplane() {
        let mut value = config();
        value.session_timeout = Some(Duration::from_millis(1_001));
        assert_eq!(value.dataplane_config(7, 9).session_timeout_secs, 2);
    }

    #[test]
    fn derives_dataplane_only_fields_internally() {
        let raw = config().dataplane_config(7, 9);
        assert_eq!(raw.bridge_ifindex, 7);
        assert_eq!(raw.uplink_ifindex, 9);
        assert_eq!(raw.v4_pool_len, 1);
        assert_eq!(raw.v4_pool[0].to_be_bytes(), [203, 0, 113, 10]);
        assert_eq!(raw.session_timeout_secs, 0);
        assert_eq!(raw._pad, [0; 3]);
    }
}
