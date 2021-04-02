//! # The HAProxy PROXY protocol.
//!
//! This defines a library to serialize and deserialize HAProxy PROXY-protocol
//! headers.
//!
//! The protocol has been implemented per the specification available here:
//! <https://www.haproxy.org/download/2.4/doc/proxy-protocol.txt>

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]

pub mod version1;
pub mod version2;

use bytes::Buf;
use snafu::{ensure, ResultExt as _, Snafu};
use std::net::IpAddr;

#[derive(Debug, Snafu)]
#[cfg_attr(not(feature = "always_exhaustive"), non_exhaustive)] // A new version may be added
pub enum Error {
    /// This is not a PROXY header at all.
    #[snafu(display("the given data is not a PROXY header"))]
    NotProxyHeader,

    /// This version of the PROXY protocol is unsupported or impossible.
    #[snafu(display("the version {} is invalid", version))]
    InvalidVersion { version: u32 },

    /// An error occurred while parsing version 1.
    #[snafu(display("there was an error while parsing the v1 header: {}", source))]
    Version1 { source: version1::Error },

    /// An error occurred while parsing version 2.
    #[snafu(display("there was an error while parsing the v2 header: {}", source))]
    Version2 { source: version2::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The PROXY header emitted at most once at the start of a new connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "always_exhaustive"), non_exhaustive)] // A new version may be added
pub enum ProxyHeader {
    /// This defines the first version specification, known as the
    /// "human-readable header format" (section 2.1), and consists of (at most)
    /// 107 bytes of data on the wire.
    Version1 {
        /// The type of IP-addresses used.
        ///
        /// If this is [version1::ProxyAddressFamily::Unknown], all the other
        /// values are zeroed. In any other case, the rest of the values must
        /// have proper values.
        family: version1::ProxyAddressFamily,

        /// The addresses used to connect to the proxy.
        addresses: version1::ProxyAddresses,
    },

    /// This defines the second version specification, known as the
    /// "binary header format" (section 2.2), and consists of a dynamic amount
    /// of bytes on the wire, depending on what information the sender wishes to
    /// convey.
    Version2 {
        /// The command of this header.
        command: version2::ProxyCommand,

        /// The protocol over which the information was transferred originally.
        transport_protocol: version2::ProxyTransportProtocol,

        /// The addresses used to connect to the proxy.
        addresses: version2::ProxyAddresses,
    },
}

fn parse_version(buf: &mut impl Buf) -> Result<u32> {
    // There is a 6 byte header to v1, 12 byte to all binary versions.
    ensure!(buf.remaining() >= 6, NotProxyHeader);

    // V1 is the only version that starts with "PROXY" (0x50 0x52 0x4F 0x58
    // 0x59), and we can therefore decide version based on that.
    //
    // We use ::chunk to not advance any bytes unnecessarily.
    if buf.chunk()[..6] == [0x50, 0x52, 0x4F, 0x58, 0x59, 0x20] {
        buf.advance(6);
        return Ok(1);
    }

    // Now we require 13: 12 for the prefix, 1 for the version + command
    ensure!(buf.remaining() >= 13, NotProxyHeader);
    ensure!(
        buf.chunk()[..12]
            == [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A],
        NotProxyHeader
    );
    buf.advance(12);

    // Note that we will now not advance the version byte on purpose, as it also
    // contains the command.
    //
    // PANIC: This is safe because we've already checked we had 13 bytes
    // available to us above, and we've only read 12 so far.
    let version = buf.chunk()[0];

    // Excerpt:
    //
    // > The next byte (the 13th one) is the protocol version and command.
    // >
    // > The highest four bits contains the version. As of this specification,
    // > it must always be sent as \x2 and the receiver must only accept this
    // > value.
    let version = version >> 4;

    Ok(version as u32)
}

/// Parse a PROXY header from the given buffer.
///
/// NOTE: The buffer must have a continuous representation of the inner data
/// available through [Buf::chunk], at the very least for the header. Data that
/// follows may be chunked as you wish.
#[must_use]
pub fn parse(buf: &mut impl Buf) -> Result<ProxyHeader> {
    let version = match parse_version(buf) {
        Ok(ver) => ver,
        Err(e) => return Err(e),
    };

    Ok(match version {
        1 => self::version1::parse(buf).context(Version1)?,
        2 => self::version2::parse(buf).context(Version2)?,
        _ => return InvalidVersion { version }.fail(),
    })
}
