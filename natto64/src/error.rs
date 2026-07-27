//! Error types exposed by the NAT64 userspace API.

use std::{error::Error as StdError, fmt, io, num::ParseIntError, path::PathBuf};

use aya::{
    EbpfError,
    maps::MapError,
    programs::{ProgramError, tc::TcError},
};

/// A result returned by the NAT64 userspace API.
pub type Result<T> = std::result::Result<T, Error>;

/// An error returned while loading, configuring, or attaching NAT64.
#[derive(Debug)]
pub enum Error {
    /// The eBPF object could not be read from disk.
    ReadEbpfObject {
        /// Object path supplied to [`crate::Nat64::load`].
        path: PathBuf,
        /// Underlying filesystem error.
        source: io::Error,
    },
    /// Aya could not load the eBPF object.
    LoadEbpfObject {
        /// Underlying Aya loader error.
        source: EbpfError,
    },
    /// The external IPv4 pool was empty.
    EmptyV4Pool,
    /// The external IPv4 pool exceeded the dataplane ABI capacity.
    V4PoolTooLarge {
        /// Number of addresses supplied by the caller.
        actual: usize,
        /// Maximum number of addresses supported by the dataplane.
        maximum: usize,
    },
    /// The configured external port range was invalid.
    InvalidPortRange {
        /// Supplied lower bound.
        port_min: u16,
        /// Supplied upper bound.
        port_max: u16,
    },
    /// The configured session timeout was zero.
    InvalidSessionTimeout,
    /// [`crate::Nat64::attach`] was called before [`crate::Nat64::configure`].
    NotConfigured,
    /// The dataplane was already attached.
    AlreadyAttached,
    /// An invalid Linux interface name was supplied.
    InvalidInterfaceName {
        /// Invalid interface name.
        interface: String,
    },
    /// A Linux interface index could not be read.
    ReadInterfaceIndex {
        /// Interface whose index was requested.
        interface: String,
        /// Underlying filesystem error.
        source: io::Error,
    },
    /// A Linux interface index contained an invalid integer.
    ParseInterfaceIndex {
        /// Interface whose index was requested.
        interface: String,
        /// Underlying integer parsing error.
        source: ParseIntError,
    },
    /// A required eBPF map was absent from the object.
    MissingMap {
        /// Required map name.
        name: &'static str,
    },
    /// The eBPF configuration map could not be opened or updated.
    ConfigureMap {
        /// Underlying Aya map error.
        source: MapError,
    },
    /// The eBPF production counters could not be opened or read.
    ReadMetrics {
        /// Underlying Aya map error.
        source: MapError,
    },
    /// Traffic-control setup failed for an interface.
    TrafficControl {
        /// Interface whose `clsact` qdisc could not be created.
        interface: String,
        /// Underlying Aya traffic-control error.
        source: TcError,
    },
    /// A required eBPF program was absent from the object.
    MissingProgram {
        /// Required program name.
        name: &'static str,
    },
    /// An eBPF classifier could not be loaded or attached.
    Program {
        /// Underlying Aya program error.
        source: ProgramError,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadEbpfObject { path, .. } => {
                write!(formatter, "failed to read eBPF object `{}`", path.display())
            }
            Self::LoadEbpfObject { .. } => formatter.write_str("failed to load eBPF object"),
            Self::EmptyV4Pool => formatter.write_str("the external IPv4 pool must not be empty"),
            Self::V4PoolTooLarge { actual, maximum } => write!(
                formatter,
                "the external IPv4 pool contains {actual} addresses, but the dataplane supports at most {maximum}"
            ),
            Self::InvalidPortRange { port_min, port_max } => write!(
                formatter,
                "invalid external port range {port_min}..={port_max}; the lower bound must be nonzero and no greater than the upper bound"
            ),
            Self::InvalidSessionTimeout => {
                formatter.write_str("the session timeout must be greater than zero")
            }
            Self::NotConfigured => {
                formatter.write_str("NAT64 must be configured before it is attached")
            }
            Self::AlreadyAttached => formatter.write_str("the NAT64 dataplane is already attached"),
            Self::InvalidInterfaceName { interface } => {
                write!(
                    formatter,
                    "`{interface}` is not a valid Linux interface name"
                )
            }
            Self::ReadInterfaceIndex { interface, .. } => {
                write!(
                    formatter,
                    "failed to read the index of interface `{interface}`"
                )
            }
            Self::ParseInterfaceIndex { interface, .. } => write!(
                formatter,
                "interface `{interface}` reported a non-numeric interface index"
            ),
            Self::MissingMap { name } => {
                write!(formatter, "required eBPF map `{name}` was not found")
            }
            Self::ConfigureMap { .. } => {
                formatter.write_str("failed to write the NAT64 dataplane configuration")
            }
            Self::ReadMetrics { .. } => {
                formatter.write_str("failed to read NAT64 production metrics")
            }
            Self::TrafficControl { interface, .. } => write!(
                formatter,
                "failed to prepare traffic control on interface `{interface}`"
            ),
            Self::MissingProgram { name } => {
                write!(formatter, "required eBPF program `{name}` was not found")
            }
            Self::Program { .. } => {
                formatter.write_str("failed to load or attach an eBPF classifier")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::ReadEbpfObject { source, .. } => Some(source),
            Self::LoadEbpfObject { source } => Some(source),
            Self::ReadInterfaceIndex { source, .. } => Some(source),
            Self::ParseInterfaceIndex { source, .. } => Some(source),
            Self::ConfigureMap { source } => Some(source),
            Self::ReadMetrics { source } => Some(source),
            Self::TrafficControl { source, .. } => Some(source),
            Self::Program { source } => Some(source),
            Self::EmptyV4Pool
            | Self::V4PoolTooLarge { .. }
            | Self::InvalidPortRange { .. }
            | Self::InvalidSessionTimeout
            | Self::NotConfigured
            | Self::AlreadyAttached
            | Self::InvalidInterfaceName { .. }
            | Self::MissingMap { .. }
            | Self::MissingProgram { .. } => None,
        }
    }
}
