use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

use crate::{Nat64, Nat64Config, RFC_6052_WELL_KNOWN_PREFIX, Result};

const DEFAULT_PORT_MIN: u16 = 20_000;
const DEFAULT_PORT_MAX: u16 = 60_000;

/// Creates a reusable builder for loading and configuring NAT64 dataplanes.
///
/// This is the recommended entry point for applications. The builder uses
/// [`RFC_6052_WELL_KNOWN_PREFIX`] and the external source-port range
/// `20000..=60000` by default. Supply at least one external IPv4 address with
/// [`Nat64Builder::with_v4_pool`] before building or attaching.
///
/// # Examples
///
/// ```no_run
/// use std::net::Ipv4Addr;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let nat64 = natto64::builder("libnatto64_ebpf.so")
///     .with_v4_pool(vec![Ipv4Addr::new(203, 0, 113, 10)])
///     .attach("br", "eth0")?;
/// # drop(nat64);
/// # Ok(())
/// # }
/// ```
#[must_use]
pub fn builder(ebpf_object: impl Into<PathBuf>) -> Nat64Builder {
    Nat64Builder {
        ebpf_object: ebpf_object.into(),
        prefix96: RFC_6052_WELL_KNOWN_PREFIX,
        v4_pool: Vec::new(),
        port_min: DEFAULT_PORT_MIN,
        port_max: DEFAULT_PORT_MAX,
        session_timeout: None,
    }
}

/// Primary configuration interface for independent [`Nat64`] dataplanes.
///
/// The standard prefix and port range are selected automatically. Most users
/// only need [`Self::with_v4_pool`] followed by one or more calls to
/// [`Self::attach`]. Each call loads an independent eBPF instance with its own
/// maps and counters.
///
/// # Reusing a builder
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let nat64 = natto64::builder("libnatto64_ebpf.so")
///     .with_v4_pool(vec!["203.0.113.10".parse()?]);
///
/// let first = nat64.attach("br-1", "eth0")?;
/// let second = nat64.attach("br-2", "eth1")?;
/// # drop((first, second));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
#[must_use]
pub struct Nat64Builder {
    ebpf_object: PathBuf,
    prefix96: [u8; 12],
    v4_pool: Vec<Ipv4Addr>,
    port_min: u16,
    port_max: u16,
    session_timeout: Option<Duration>,
}

impl Nat64Builder {
    /// Overrides the `/96` IPv6 prefix translated by each dataplane.
    ///
    /// The default is [`RFC_6052_WELL_KNOWN_PREFIX`] (`64:ff9b::/96`).
    pub fn with_prefix96(mut self, prefix96: [u8; 12]) -> Self {
        self.prefix96 = prefix96;
        self
    }

    /// Sets the external IPv4 addresses available to translated connections.
    ///
    /// This is the only required builder setting. At least one address is
    /// required and at most 16 addresses are supported.
    pub fn with_v4_pool(mut self, v4_pool: Vec<Ipv4Addr>) -> Self {
        self.v4_pool = v4_pool;
        self
    }

    /// Overrides the lowest external TCP or UDP source port, inclusive.
    ///
    /// The default is `20000`.
    pub fn with_port_min(mut self, port_min: u16) -> Self {
        self.port_min = port_min;
        self
    }

    /// Overrides the highest external TCP or UDP source port, inclusive.
    ///
    /// The default is `60000`.
    pub fn with_port_max(mut self, port_max: u16) -> Self {
        self.port_max = port_max;
        self
    }

    /// Sets the idle timeout enforced by per-session kernel BPF timers.
    ///
    /// `None` disables expiration. Timers run in the kernel; no userspace runtime
    /// or map scan is required. Durations are rounded up to whole seconds.
    pub fn with_session_timeouts(mut self, session_timeout: Option<Duration>) -> Self {
        self.session_timeout = session_timeout;
        self
    }

    /// Loads a new eBPF instance and applies the configured NAT64 policy.
    ///
    /// The returned dataplane is not attached. Use this advanced lifecycle path
    /// when the interface names are not known yet or attachment must happen in a
    /// separate step. Most applications can call [`Self::attach`] directly.
    ///
    /// The builder remains reusable and can create additional independent
    /// dataplanes.
    ///
    /// # Errors
    ///
    /// Returns an error if the eBPF object cannot be read or loaded, or if the
    /// IPv4 pool, port range, or session timeout is invalid.
    pub fn build(&self) -> Result<Nat64> {
        let mut nat64 = Nat64::load(&self.ebpf_object)?;
        nat64.configure(self.config())?;
        Ok(nat64)
    }

    /// Loads, configures, and attaches a new independent NAT64 dataplane.
    ///
    /// This is the recommended finishing method for the builder. It returns an
    /// attached [`Nat64`] value, so the caller does not need a mutable binding.
    ///
    /// The builder remains reusable, so this method can be called repeatedly for
    /// different bridge and uplink pairs. Each returned [`Nat64`] owns a separate
    /// eBPF instance with independent maps and counters.
    ///
    /// # Errors
    ///
    /// Returns any loading, configuration, interface-resolution, traffic-control,
    /// or eBPF attachment error.
    pub fn attach(&self, bridge: &str, uplink: &str) -> Result<Nat64> {
        let mut nat64 = self.build()?;
        nat64.attach(bridge, uplink)?;
        Ok(nat64)
    }

    fn config(&self) -> Nat64Config {
        Nat64Config {
            prefix96: self.prefix96,
            v4_pool: self.v4_pool.clone(),
            port_min: self.port_min,
            port_max: self.port_max,
            session_timeout: self.session_timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_standard_defaults() {
        let v4_pool = vec![Ipv4Addr::new(203, 0, 113, 10)];
        let builder = builder("libnatto64_ebpf.so").with_v4_pool(v4_pool);
        let config = builder.config();

        assert_eq!(config.prefix96, RFC_6052_WELL_KNOWN_PREFIX);
        assert_eq!(config.port_min, 20_000);
        assert_eq!(config.port_max, 60_000);
        assert_eq!(builder.session_timeout, None);
    }

    #[test]
    fn supports_policy_overrides() {
        let prefix96 = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let v4_pool = vec![Ipv4Addr::new(198, 51, 100, 20)];
        let builder = builder("libnatto64_ebpf.so")
            .with_prefix96(prefix96)
            .with_v4_pool(v4_pool.clone())
            .with_port_min(30_000)
            .with_port_max(40_000)
            .with_session_timeouts(Some(Duration::from_secs(300)));
        let config = builder.config();

        assert_eq!(config.prefix96, prefix96);
        assert_eq!(config.v4_pool, v4_pool);
        assert_eq!(config.port_min, 30_000);
        assert_eq!(config.port_max, 40_000);
        assert_eq!(builder.session_timeout, Some(Duration::from_secs(300)));
    }
}
