#![no_std]
#![deny(missing_docs)]
//! Allocation-free packet translation primitives shared by natto64 components.

/// Internet-checksum helpers for IPv4, IPv6, TCP, and UDP.
pub mod checksum;
/// Builders for fixed-size IPv4 and IPv6 headers.
pub mod headers;
/// Helpers for reading and writing big-endian integer values.
pub mod wire;
