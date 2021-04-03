use bytes::{Buf, BufMut as _, BytesMut};
use snafu::{ensure, OptionExt as _, ResultExt as _, Snafu};
use std::{
    io::Write as _,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    str::{FromStr as _, Utf8Error},
};

const CR: u8 = 0x0D;
const LF: u8 = 0x0A;

#[derive(Debug, Snafu)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum ParseError {
    #[snafu(display("an unexpected eof was hit"))]
    UnexpectedEof,

    #[snafu(display("an illegal address family was presented"))]
    IllegalAddressFamily,

    #[snafu(display("the given input is not valid ascii text"))]
    NonAscii { source: Utf8Error },

    #[snafu(display("the given input misses an address"))]
    MissingAddress,

    #[snafu(display("invalid ip address"))]
    InvalidAddress { source: AddrParseError },

    #[snafu(display("invalid port"))]
    InvalidPort,

    #[snafu(display("illegal header ending"))]
    IllegalHeaderEnding,
}

#[derive(Debug, Snafu)]
pub enum EncodeError {
    #[snafu(display("could not write to the buffer"))]
    StdIo { source: std::io::Error },
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ProxyAddressFamily {
    Unknown,
    Tcp4,
    Tcp6,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ProxyAddresses {
    Unknown,
    Ipv4 {
        source: SocketAddrV4,
        destination: SocketAddrV4,
    },
    Ipv6 {
        source: SocketAddrV6,
        destination: SocketAddrV6,
    },
}

fn count_till_first(haystack: &[u8], needle: u8) -> Option<usize> {
    for (idx, &b) in haystack.iter().enumerate() {
        if b == needle {
            return Some(idx);
        }
    }

    None
}

pub(crate) fn parse(buf: &mut impl Buf) -> Result<super::ProxyHeader, ParseError> {
    ensure!(buf.remaining() >= 4, UnexpectedEof);

    let step = buf.get_u8();
    let address_family = match step {
        b'T' => {
            // Tcp4 / Tcp6
            buf.advance(2);
            let version = buf.get_u8();
            match version {
                b'4' => ProxyAddressFamily::Tcp4,
                b'6' => ProxyAddressFamily::Tcp6,
                _ => return IllegalAddressFamily.fail(),
            }
        }
        b'U' => {
            // Unknown
            ensure!(buf.remaining() >= 6, UnexpectedEof); // Not 7, we consumed 1.
            buf.advance(6);
            ProxyAddressFamily::Unknown
        }
        _ => return IllegalAddressFamily.fail(),
    };

    if address_family == ProxyAddressFamily::Unknown {
        // Just consume up to the end.
        let mut cr = false;
        loop {
            ensure!(buf.has_remaining(), UnexpectedEof);
            let b = buf.get_u8();
            if cr && b == LF {
                break;
            }
            cr = b == CR;
        }
        return Ok(super::ProxyHeader::Version1 {
            family: address_family,
            addresses: ProxyAddresses::Unknown,
        });
    }

    // 1 space, 4 digits, 3 dots, absolute minimum for the source.
    ensure!(buf.remaining() >= 8, UnexpectedEof);
    buf.advance(1); // Space

    let count = count_till_first(buf.chunk(), b' ').context(MissingAddress)?;
    let source = &buf.chunk()[..count];
    let source = std::str::from_utf8(source).context(NonAscii)?;
    let source = match address_family {
        ProxyAddressFamily::Tcp4 => IpAddr::V4(Ipv4Addr::from_str(source).context(InvalidAddress)?),
        ProxyAddressFamily::Tcp6 => IpAddr::V6(Ipv6Addr::from_str(source).context(InvalidAddress)?),
        ProxyAddressFamily::Unknown => unreachable!("unknown should have its own branch"),
    };
    buf.advance(count);

    // Same as above, another address incoming.
    ensure!(buf.remaining() >= 8, UnexpectedEof);
    buf.advance(1); // Space

    let count = count_till_first(buf.chunk(), b' ').context(MissingAddress)?;
    let destination = &buf.chunk()[..count];
    let destination = std::str::from_utf8(destination).context(NonAscii)?;
    let destination = match address_family {
        ProxyAddressFamily::Tcp4 => {
            IpAddr::V4(Ipv4Addr::from_str(destination).context(InvalidAddress)?)
        }
        ProxyAddressFamily::Tcp6 => {
            IpAddr::V6(Ipv6Addr::from_str(destination).context(InvalidAddress)?)
        }
        ProxyAddressFamily::Unknown => unreachable!("unknown should have its own branch"),
    };
    buf.advance(count);

    // Space, then a port. 0 is minimum valid port, so 1 byte.
    ensure!(buf.remaining() >= 2, UnexpectedEof);
    buf.advance(1);

    let count = count_till_first(buf.chunk(), b' ').context(InvalidPort)?;
    let source_port = &buf.chunk()[..count];
    let source_port = std::str::from_utf8(source_port).context(NonAscii)?;
    ensure!(
        // The port 0 is itself valid, but 01 is not.
        !source_port.starts_with('0') || source_port == "0",
        InvalidPort,
    );
    let source_port: u16 = source_port.parse().ok().context(InvalidPort)?;
    buf.advance(count);

    // Space, then a port, then CRLF. 0 is minimum valid port, so 1 byte.
    ensure!(buf.remaining() >= 4, UnexpectedEof);
    buf.advance(1);

    // This is the last member of the string. Read until CR; that's next up.
    let count = count_till_first(buf.chunk(), CR).context(InvalidPort)?;
    let destination_port = &buf.chunk()[..count];
    let destination_port = std::str::from_utf8(destination_port).context(NonAscii)?;
    ensure!(
        // The port 0 is itself valid, but 01 is not.
        !destination_port.starts_with('0') || destination_port == "0",
        InvalidPort,
    );
    let destination_port: u16 = destination_port.parse().ok().context(InvalidPort)?;
    buf.advance(count);

    ensure!(buf.get_u8() == CR, IllegalHeaderEnding);
    ensure!(buf.get_u8() == LF, IllegalHeaderEnding);

    let addresses = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => ProxyAddresses::Ipv4 {
            source: SocketAddrV4::new(source, source_port),
            destination: SocketAddrV4::new(destination, destination_port),
        },
        (IpAddr::V6(source), IpAddr::V6(destination)) => ProxyAddresses::Ipv6 {
            source: SocketAddrV6::new(source, source_port, 0, 0),
            destination: SocketAddrV6::new(destination, destination_port, 0, 0),
        },
        // Mismatches are checked before reading ports.
        _ => unreachable!(),
    };

    Ok(super::ProxyHeader::Version1 {
        family: address_family,
        addresses,
    })
}

pub(crate) fn encode(addresses: ProxyAddresses) -> Result<BytesMut, EncodeError> {
    if let ProxyAddresses::Unknown = addresses {
        return Ok(BytesMut::from(&b"PROXY UNKNOWN\r\n"[..]));
    }

    // Reserve as much data as we're gonna need -- at most.
    let mut buf = BytesMut::with_capacity(107).writer();
    buf.write_all(&b"PROXY TCP"[..]).context(StdIo)?;

    match addresses {
        ProxyAddresses::Ipv4 {
            source,
            destination,
        } => {
            buf.write(&b"4 "[..]).context(StdIo)?;
            write!(
                buf,
                "{} {} {} {}\r\n",
                source.ip(),
                destination.ip(),
                source.port(),
                destination.port(),
            )
            .context(StdIo)?;
        }
        ProxyAddresses::Ipv6 {
            source,
            destination,
        } => {
            buf.write(&b"6 "[..]).context(StdIo)?;
            write!(
                buf,
                "{} {} {} {}\r\n",
                source.ip(),
                destination.ip(),
                source.port(),
                destination.port(),
            )
            .context(StdIo)?;
        }
        ProxyAddresses::Unknown => unreachable!(),
    }

    Ok(buf.into_inner())
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::ProxyHeader;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use rand::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_valid_unknown_cases() {
        let unknown = Ok(ProxyHeader::Version1 {
            family: ProxyAddressFamily::Unknown,
            addresses: ProxyAddresses::Unknown,
        });
        assert_eq!(parse(&mut &b"UNKNOWN\r\n"[..]), unknown);
        assert_eq!(
            parse(&mut &b"UNKNOWN this is bogus data!\r\r\r\n"[..]),
            unknown,
        );
        assert_eq!(
            parse(&mut &b"UNKNOWN 192.168.0.1 192.168.1.1 123 321\r\n"[..]),
            unknown,
        );

        let mut random = [0u8; 128];
        rand::thread_rng().fill_bytes(&mut random);
        let mut header = b"UNKNOWN ".to_vec();
        header.extend(&random[..]);
        header.extend(b"\r\n");
        let mut buf = Bytes::from(header);
        assert_eq!(parse(&mut buf), unknown);
        assert!(!buf.has_remaining()); // Consume the ENTIRE header!
    }

    #[test]
    fn test_valid_ipv4_cases() {
        fn valid(
            (a, b, c, d): (u8, u8, u8, u8),
            e: u16,
            (f, g, h, i): (u8, u8, u8, u8),
            j: u16,
        ) -> ProxyHeader {
            ProxyHeader::Version1 {
                family: ProxyAddressFamily::Tcp4,
                addresses: ProxyAddresses::Ipv4 {
                    source: SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), e),
                    destination: SocketAddrV4::new(Ipv4Addr::new(f, g, h, i), j),
                },
            }
        }
        assert_eq!(
            parse(&mut &b"TCP4 192.168.201.102 1.2.3.4 0 65535\r\n"[..]),
            Ok(valid((192, 168, 201, 102), 0, (1, 2, 3, 4), 65535)),
        );
        assert_eq!(
            parse(&mut &b"TCP4 0.0.0.0 0.0.0.0 0 0\r\n"[..]),
            Ok(valid((0, 0, 0, 0), 0, (0, 0, 0, 0), 0)),
        );
        assert_eq!(
            parse(&mut &b"TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"[..]),
            Ok(valid(
                (255, 255, 255, 255),
                65535,
                (255, 255, 255, 255),
                65535,
            )),
        );
    }

    #[test]
    fn test_valid_ipv6_cases() {
        fn valid(
            (a, b, c, d, e, f, g, h): (u16, u16, u16, u16, u16, u16, u16, u16),
            i: u16,
            (j, k, l, m, n, o, p, q): (u16, u16, u16, u16, u16, u16, u16, u16),
            r: u16,
        ) -> ProxyHeader {
            ProxyHeader::Version1 {
                family: ProxyAddressFamily::Tcp6,
                addresses: ProxyAddresses::Ipv6 {
                    source: SocketAddrV6::new(Ipv6Addr::new(a, b, c, d, e, f, g, h), i, 0, 0),
                    destination: SocketAddrV6::new(Ipv6Addr::new(j, k, l, m, n, o, p, q), r, 0, 0),
                },
            }
        }
        assert_eq!(
            parse(&mut &b"TCP6 ab:ce:ef:01:23:45:67:89 ::1 0 65535\r\n"[..]),
            Ok(valid(
                (0xAB, 0xCE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89),
                0,
                (0, 0, 0, 0, 0, 0, 0, 1),
                65535,
            )),
        );
        assert_eq!(
            parse(&mut &b"TCP6 :: :: 0 0\r\n"[..]),
            Ok(valid(
                (0, 0, 0, 0, 0, 0, 0, 0),
                0,
                (0, 0, 0, 0, 0, 0, 0, 0),
                0,
            )),
        );
        assert_eq!(
            parse(
                &mut &b"TCP6 ff:ff:ff:ff:ff:ff:ff:ff ff:ff:ff:ff:ff:ff:ff:ff 65535 65535\r\n"[..],
            ),
            Ok(valid(
                (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
                65535,
                (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
                65535,
            )),
        );
    }

    #[test]
    fn test_invalid_cases() {
        assert_eq!(
            parse(&mut &b"UNKNOWN \r"[..]),
            Err(ParseError::UnexpectedEof)
        );
        assert_eq!(
            parse(&mut &b"UNKNOWN \r\t\t\r"[..]),
            Err(ParseError::UnexpectedEof),
        );
        assert_eq!(
            parse(&mut &b"UNKNOWN\r\r\r\r\rHello, world!"[..]),
            Err(ParseError::UnexpectedEof),
        );
        assert_eq!(
            parse(&mut &b"UNKNOWN\nGET /index.html HTTP/1.0"[..]),
            Err(ParseError::UnexpectedEof),
        );
        assert_eq!(
            parse(&mut &b"UNKNOWN\n"[..]),
            Err(ParseError::UnexpectedEof)
        );
    }

    #[test]
    fn test_crlf() {
        assert_eq!(CR, b'\r');
        assert_eq!(LF, b'\n');
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_unknown() {
        let encoded = encode(ProxyAddresses::Unknown);
        assert!(matches!(encoded, Ok(_)));
        assert_eq!(encoded.unwrap(), &b"PROXY UNKNOWN\r\n"[..]);
    }

    #[test]
    fn test_tcp4() {
        let encoded = encode(ProxyAddresses::Ipv4 {
            source: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 987),
            destination: SocketAddrV4::new(Ipv4Addr::new(255, 254, 253, 252), 12345),
        });
        assert!(matches!(encoded, Ok(_)));
        assert_eq!(
            encoded.unwrap(),
            Bytes::from_static(&b"PROXY TCP4 1.2.3.4 255.254.253.252 987 12345\r\n"[..]),
        );
    }

    #[test]
    fn test_tcp6() {
        let encoded = encode(ProxyAddresses::Ipv6 {
            source: SocketAddrV6::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 987, 0, 0),
            destination: SocketAddrV6::new(
                Ipv6Addr::new(65535, 65534, 65533, 65532, 0, 1, 2, 3),
                12345,
                0,
                0,
            ),
        });
        assert!(matches!(encoded, Ok(_)));
        assert_eq!(
            encoded.unwrap(),
            Bytes::from_static(
                &b"PROXY TCP6 1:2:3:4:5:6:7:8 ffff:fffe:fffd:fffc:0:1:2:3 987 12345\r\n"[..],
            ),
        );

        let encoded = encode(ProxyAddresses::Ipv6 {
            source: SocketAddrV6::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 987, 0, 0),
            destination: SocketAddrV6::new(
                Ipv6Addr::new(65535, 65534, 0, 0, 0, 1, 2, 3),
                12345,
                0,
                0,
            ),
        });
        assert!(matches!(encoded, Ok(_)));
        assert_eq!(
            encoded.unwrap(),
            Bytes::from_static(&b"PROXY TCP6 1:2:3:4:5:6:7:8 ffff:fffe::1:2:3 987 12345\r\n"[..]),
        );

        let encoded = encode(ProxyAddresses::Ipv6 {
            source: SocketAddrV6::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 987, 0, 0),
            destination: SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 1, 2, 3), 12345, 0, 0),
        });
        assert!(matches!(encoded, Ok(_)));
        assert_eq!(
            encoded.unwrap(),
            Bytes::from_static(&b"PROXY TCP6 1:2:3:4:5:6:7:8 ::1:2:3 987 12345\r\n"[..]),
        );
    }
}
