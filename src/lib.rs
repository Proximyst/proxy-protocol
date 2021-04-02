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

#[derive(Debug, Snafu)]
#[cfg_attr(not(feature = "always_exhaustive"), non_exhaustive)] // A new version may be added
#[cfg_attr(test, derive(PartialEq, Eq))]
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
    if buf.chunk()[..6] == [b'P', b'R', b'O', b'X', b'Y', b' '] {
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

    // Interesting edge-case! This is the only time version 1 would be invalid.
    if version == 1 {
        return InvalidVersion { version: 1u32 }.fail();
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProxyHeader;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use rand::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_version1() {
        let unknown = Ok(ProxyHeader::Version1 {
            family: version1::ProxyAddressFamily::Unknown,
            addresses: version1::ProxyAddresses::Unknown,
        });
        assert_eq!(parse(&mut &b"PROXY UNKNOWN\r\n"[..]), unknown);
        assert_eq!(
            parse(&mut &b"PROXY UNKNOWN this is bogus data!\r\r\r\n"[..]),
            unknown,
        );
        assert_eq!(
            parse(&mut &b"PROXY UNKNOWN 192.168.0.1 192.168.1.1 123 321\r\n"[..]),
            unknown,
        );

        let mut random = [0u8; 128];
        rand::thread_rng().fill_bytes(&mut random);
        let mut header = b"PROXY UNKNOWN ".to_vec();
        header.extend(&random[..]);
        header.extend(b"\r\n");
        let mut buf = Bytes::from(header);
        assert_eq!(parse(&mut buf), unknown);
        assert!(!buf.has_remaining()); // Consume the ENTIRE header!

        fn valid_v4(
            (a, b, c, d): (u8, u8, u8, u8),
            e: u16,
            (f, g, h, i): (u8, u8, u8, u8),
            j: u16,
        ) -> ProxyHeader {
            ProxyHeader::Version1 {
                family: version1::ProxyAddressFamily::Tcp4,
                addresses: version1::ProxyAddresses::Ipv4 {
                    source: SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), e),
                    destination: SocketAddrV4::new(Ipv4Addr::new(f, g, h, i), j),
                },
            }
        }

        assert_eq!(
            parse(&mut &b"PROXY TCP4 192.168.201.102 1.2.3.4 0 65535\r\n"[..]),
            Ok(valid_v4((192, 168, 201, 102), 0, (1, 2, 3, 4), 65535)),
        );
        assert_eq!(
            parse(&mut &b"PROXY TCP4 0.0.0.0 0.0.0.0 0 0\r\n"[..]),
            Ok(valid_v4((0, 0, 0, 0), 0, (0, 0, 0, 0), 0)),
        );
        assert_eq!(
            parse(&mut &b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"[..]),
            Ok(valid_v4(
                (255, 255, 255, 255),
                65535,
                (255, 255, 255, 255),
                65535,
            )),
        );

        fn valid_v6(
            (a, b, c, d, e, f, g, h): (u16, u16, u16, u16, u16, u16, u16, u16),
            i: u16,
            (j, k, l, m, n, o, p, q): (u16, u16, u16, u16, u16, u16, u16, u16),
            r: u16,
        ) -> ProxyHeader {
            ProxyHeader::Version1 {
                family: version1::ProxyAddressFamily::Tcp6,
                addresses: version1::ProxyAddresses::Ipv6 {
                    source: SocketAddrV6::new(Ipv6Addr::new(a, b, c, d, e, f, g, h), i, 0, 0),
                    destination: SocketAddrV6::new(Ipv6Addr::new(j, k, l, m, n, o, p, q), r, 0, 0),
                },
            }
        }
        assert_eq!(
            parse(&mut &b"PROXY TCP6 ab:ce:ef:01:23:45:67:89 ::1 0 65535\r\n"[..]),
            Ok(valid_v6(
                (0xAB, 0xCE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89),
                0,
                (0, 0, 0, 0, 0, 0, 0, 1),
                65535,
            )),
        );
        assert_eq!(
            parse(&mut &b"PROXY TCP6 :: :: 0 0\r\n"[..]),
            Ok(valid_v6(
                (0, 0, 0, 0, 0, 0, 0, 0),
                0,
                (0, 0, 0, 0, 0, 0, 0, 0),
                0,
            )),
        );
        assert_eq!(
            parse(
                &mut &b"PROXY TCP6 ff:ff:ff:ff:ff:ff:ff:ff ff:ff:ff:ff:ff:ff:ff:ff 65535 65535\r\n"
                    [..],
            ),
            Ok(valid_v6(
                (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
                65535,
                (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
                65535,
            )),
        );

        assert_eq!(
            parse(&mut &b"PROXY UNKNOWN \r"[..]),
            Err(Error::Version1 {
                source: version1::Error::UnexpectedEof,
            }),
        );
        assert_eq!(
            parse(&mut &b"PROXY UNKNOWN \r\t\t\r"[..]),
            Err(Error::Version1 {
                source: version1::Error::UnexpectedEof,
            }),
        );
        assert_eq!(
            parse(&mut &b"PROXY UNKNOWN\r\r\r\r\rHello, world!"[..]),
            Err(Error::Version1 {
                source: version1::Error::UnexpectedEof,
            }),
        );
        assert_eq!(
            parse(&mut &b"PROXY UNKNOWN\nGET /index.html HTTP/1.0"[..]),
            Err(Error::Version1 {
                source: version1::Error::UnexpectedEof,
            }),
        );
        assert_eq!(
            parse(&mut &b"PROXY UNKNOWN\n"[..]),
            Err(Error::Version1 {
                source: version1::Error::UnexpectedEof,
            }),
        );
    }

    #[test]
    fn test_version2() {
        const PREFIX_LOCAL: [u8; 13] = [
            0x0D,
            0x0A,
            0x0D,
            0x0A,
            0x00,
            0x0D,
            0x0A,
            0x51,
            0x55,
            0x49,
            0x54,
            0x0A,
            (2 << 4) | 0,
        ];
        const PREFIX_PROXY: [u8; 13] = [
            0x0D,
            0x0A,
            0x0D,
            0x0A,
            0x00,
            0x0D,
            0x0A,
            0x51,
            0x55,
            0x49,
            0x54,
            0x0A,
            (2 << 4) | 1,
        ];

        assert_eq!(
            parse(&mut [&PREFIX_LOCAL[..], &[0u8; 16][..]].concat().as_slice()),
            Ok(ProxyHeader::Version2 {
                command: version2::ProxyCommand::Local,
                addresses: version2::ProxyAddresses::Unspec,
                transport_protocol: version2::ProxyTransportProtocol::Unspec,
            }),
        );
        assert_eq!(
            parse(&mut [&PREFIX_PROXY[..], &[0u8; 16][..]].concat().as_slice()),
            Ok(ProxyHeader::Version2 {
                command: version2::ProxyCommand::Proxy,
                addresses: version2::ProxyAddresses::Unspec,
                transport_protocol: version2::ProxyTransportProtocol::Unspec,
            }),
        );

        assert_eq!(
            parse(
                &mut [
                    &PREFIX_PROXY[..],
                    &[
                        // Inet << 4 | Stream
                        (1 << 4) | 1,
                        // Length beyond this: 12
                        // Let's throw in a TLV with no data; 3 bytes.
                        0,
                        15,
                        // Source IP
                        127,
                        0,
                        0,
                        1,
                        // Source port
                        // 65535 = [255, 255]
                        255,
                        255,
                        // Destination IP
                        192,
                        168,
                        0,
                        1,
                        // Destination port
                        // 257 = [1, 1]
                        1,
                        1,
                        // TLV
                        69,
                        0,
                        0,
                    ][..]
                ]
                .concat()
                .as_slice(),
            ),
            Ok(ProxyHeader::Version2 {
                command: version2::ProxyCommand::Proxy,
                transport_protocol: version2::ProxyTransportProtocol::Stream,
                addresses: version2::ProxyAddresses::Ipv4 {
                    source: (Ipv4Addr::new(127, 0, 0, 1), Some(65535)),
                    destination: (Ipv4Addr::new(192, 168, 0, 1), Some(257)),
                },
            })
        );

        let mut data = Bytes::from(
            [
                &PREFIX_LOCAL[..],
                &[
                    // Inet << 4 | Datagram
                    (1 << 4) | 2,
                    // Length beyond this: 12
                    0,
                    12,
                    // Source IP
                    0,
                    0,
                    0,
                    0,
                    // Source port
                    0,
                    0,
                    // Destination IP
                    255,
                    255,
                    255,
                    255,
                    // Destination port
                    255,
                    0,
                    // Extra data
                    1,
                    2,
                    3,
                    4,
                ][..],
            ]
            .concat(),
        );
        assert_eq!(
            parse(&mut data),
            Ok(ProxyHeader::Version2 {
                command: version2::ProxyCommand::Local,
                transport_protocol: version2::ProxyTransportProtocol::Datagram,
                addresses: version2::ProxyAddresses::Ipv4 {
                    source: (Ipv4Addr::new(0, 0, 0, 0), Some(0)),
                    destination: (Ipv4Addr::new(255, 255, 255, 255), Some(255 << 8)),
                },
            })
        );
        assert!(data.remaining() == 4); // Consume the entire header

        assert_eq!(
            parse(
                &mut [
                    &PREFIX_PROXY[..],
                    &[
                        // Inet6 << 4 | Datagram
                        (2 << 4) | 2,
                        // Length beyond this: 12
                        // Let's throw in a TLV with no data; 3 bytes.
                        0,
                        39,
                        // Source IP
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        255,
                        // Source port
                        // 65535 = [255, 255]
                        255,
                        255,
                        // Destination IP
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        // Destination port
                        // 257 = [1, 1]
                        1,
                        1,
                        // TLV
                        69,
                        0,
                        0,
                    ][..],
                ]
                .concat()
                .as_slice(),
            ),
            Ok(ProxyHeader::Version2 {
                command: version2::ProxyCommand::Proxy,
                transport_protocol: version2::ProxyTransportProtocol::Datagram,
                addresses: version2::ProxyAddresses::Ipv6 {
                    source: (
                        Ipv6Addr::new(65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535),
                        Some(65535),
                    ),
                    destination: (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), Some(257)),
                },
            })
        );

        let mut data = Bytes::from(
            [
                &PREFIX_LOCAL[..],
                &[
                    // Inet6 << 4 | Stream
                    (2 << 4) | 1,
                    // Length beyond this: 12
                    0,
                    36,
                    // Source IP
                    81,
                    92,
                    0,
                    52,
                    83,
                    12,
                    255,
                    68,
                    19,
                    5,
                    111,
                    200,
                    54,
                    90,
                    55,
                    66,
                    // Source port
                    123,
                    0,
                    // Destination IP
                    255,
                    255,
                    255,
                    255,
                    0,
                    0,
                    0,
                    0,
                    123,
                    123,
                    69,
                    69,
                    21,
                    21,
                    42,
                    42,
                    // Destination port
                    255,
                    255,
                    // Extra data
                    1,
                    2,
                    3,
                    4,
                ][..],
            ]
            .concat(),
        );
        assert_eq!(
            parse(&mut data),
            Ok(ProxyHeader::Version2 {
                command: version2::ProxyCommand::Local,
                transport_protocol: version2::ProxyTransportProtocol::Stream,
                addresses: version2::ProxyAddresses::Ipv6 {
                    source: (
                        Ipv6Addr::new(20828, 52, 21260, 65348, 4869, 28616, 13914, 14146),
                        Some(31488),
                    ),
                    destination: (
                        Ipv6Addr::new(65535, 65535, 0, 0, 31611, 17733, 5397, 10794),
                        Some(65535),
                    ),
                },
            })
        );
        assert!(data.remaining() == 4); // Consume the entire header

        let mut data = [0u8; 200];
        rand::thread_rng().fill_bytes(&mut data);
        data[0] = 99; // Make 100% sure it's invalid.
        assert!(parse(&mut &data[..]).is_err());

        assert_eq!(
            parse(&mut &PREFIX_LOCAL[..]),
            Err(Error::Version2 {
                source: version2::Error::UnexpectedEof,
            }),
        );

        assert_eq!(
            parse(
                &mut [
                    &PREFIX_PROXY[..],
                    &[
                        // Inet << 4 | Stream
                        (1 << 4) | 1,
                        // Length beyond this: 12
                        // 3 bytes is clearly too few if we expect 2 IPv4s and ports
                        0,
                        3,
                    ][..],
                ]
                .concat()
                .as_slice(),
            ),
            Err(Error::Version2 {
                source: version2::Error::InsufficientLengthSpecified {
                    given: 3,
                    needs: 4 * 2 + 2 * 2,
                },
            }),
        );
    }

    #[test]
    fn test_unknown_version() {
        assert_eq!(
            parse_version(
                &mut &[
                    0x0D,
                    0x0A,
                    0x0D,
                    0x0A,
                    0x00,
                    0x0D,
                    0x0A,
                    0x51,
                    0x55,
                    0x49,
                    0x54,
                    0x0A,
                    1 << 4, // Version goes in upper half of the byte
                ][..],
            ),
            Err(Error::InvalidVersion { version: 1 }),
        );
    }

    #[test]
    fn test_version_parsing_correct() {
        assert_eq!(
            parse_version(&mut &[b'P', b'R', b'O', b'X', b'Y', b' '][..]),
            Ok(1),
        );
        assert_eq!(
            parse_version(
                &mut &[
                    0x0D,
                    0x0A,
                    0x0D,
                    0x0A,
                    0x00,
                    0x0D,
                    0x0A,
                    0x51,
                    0x55,
                    0x49,
                    0x54,
                    0x0A,
                    15 << 4, // Version goes in upper half of the byte
                ][..],
            ),
            Ok(15),
        );
    }

    #[test]
    fn test_version_parsing_errors() {
        assert_eq!(
            parse_version(&mut &b"Proximyst"[..]),
            Err(Error::NotProxyHeader)
        );
    }
}
