use bytes::Buf;
use snafu::{ensure, Snafu};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Snafu)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Error {
    #[snafu(display("an unexpected eof was hit"))]
    UnexpectedEof,

    #[snafu(display("invalid command: {}", cmd))]
    UnknownCommand { cmd: u8 },

    #[snafu(display("invalid address family: {}", family))]
    UnknownAddressFamily { family: u8 },

    #[snafu(display("invalid transport protocol: {}", protocol))]
    UnknownTransportProtocol { protocol: u8 },

    #[snafu(display("insufficient length specified: {}, requires minimum {}", given, needs))]
    InsufficientLengthSpecified { given: usize, needs: usize },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ProxyCommand {
    Local,
    Proxy,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ProxyTransportProtocol {
    Unspec,
    Stream,
    Datagram,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ProxyAddresses {
    Unspec,
    Ipv4 {
        source: (Ipv4Addr, Option<u16>),
        destination: (Ipv4Addr, Option<u16>),
    },
    Ipv6 {
        source: (Ipv6Addr, Option<u16>),
        destination: (Ipv6Addr, Option<u16>),
    },
    Unix {
        source: [u8; 108],
        destination: [u8; 108],
    },
}

#[derive(PartialEq, Eq)]
enum ProxyAddressFamily {
    Unspec,
    Inet,
    Inet6,
    Unix,
}

pub(crate) fn parse(buf: &mut impl Buf) -> Result<super::ProxyHeader> {
    // We need to parse the following:
    //
    // > struct proxy_hdr_v2 {
    // >     uint8_t sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    // >     uint8_t ver_cmd;  /* protocol version and command */
    // >     uint8_t fam;      /* protocol family and address */
    // >     uint16_t len;     /* number of following bytes part of the header */
    // > };
    //
    // `uint8_t *sig` was parsed in our caller.
    // We have ver_cmd next up; version is already parsed.

    // No ensure for command byte. We know it must exist.
    let command = buf.get_u8() << 4 >> 4;
    let command = match command {
        0 => ProxyCommand::Local,
        1 => ProxyCommand::Proxy,
        cmd => return UnknownCommand { cmd }.fail(),
    };

    // 4 bits for address family, 4 bits for transport protocol,
    // then 2 bytes for the length.
    ensure!(buf.remaining() >= 3, UnexpectedEof);

    let byte = buf.get_u8();
    let address_family = match byte >> 4 {
        0 => ProxyAddressFamily::Unspec,
        1 => ProxyAddressFamily::Inet,
        2 => ProxyAddressFamily::Inet6,
        3 => ProxyAddressFamily::Unix,
        family => return UnknownAddressFamily { family }.fail(),
    };
    let transport_protocol = match byte << 4 >> 4 {
        0 => ProxyTransportProtocol::Unspec,
        1 => ProxyTransportProtocol::Stream,
        2 => ProxyTransportProtocol::Datagram,
        protocol => return UnknownTransportProtocol { protocol }.fail(),
    };

    let length = buf.get_u16() as usize;

    if address_family == ProxyAddressFamily::Unspec {
        // We have no information to parse.
        ensure!(buf.remaining() >= length, UnexpectedEof);
        buf.advance(length);

        return Ok(super::ProxyHeader::Version2 {
            command,
            transport_protocol,
            addresses: ProxyAddresses::Unspec,
        });
    }

    // Time to parse the following:
    //
    // > union proxy_addr {
    // >     struct {        /* for TCP/UDP over IPv4, len = 12 */
    // >         uint32_t src_addr;
    // >         uint32_t dst_addr;
    // >         uint16_t src_port;
    // >         uint16_t dst_port;
    // >     } ipv4_addr;
    // >     struct {        /* for TCP/UDP over IPv6, len = 36 */
    // >          uint8_t  src_addr[16];
    // >          uint8_t  dst_addr[16];
    // >          uint16_t src_port;
    // >          uint16_t dst_port;
    // >     } ipv6_addr;
    // >     struct {        /* for AF_UNIX sockets, len = 216 */
    // >          uint8_t src_addr[108];
    // >          uint8_t dst_addr[108];
    // >     } unix_addr;
    // > };

    if address_family == ProxyAddressFamily::Unix {
        ensure!(
            length >= 108 * 2,
            InsufficientLengthSpecified {
                given: length,
                needs: 108usize * 2,
            },
        );
        ensure!(buf.remaining() >= 108 * 2, UnexpectedEof);
        let mut source = [0u8; 108];
        let mut destination = [0u8; 108];
        buf.copy_to_slice(&mut source[..]);
        buf.copy_to_slice(&mut destination[..]);
        // TODO(Mariell Hoversholm): Support TLVs
        if length > 108 * 2 {
            buf.advance(length - (108 * 2));
        }

        return Ok(super::ProxyHeader::Version2 {
            command,
            transport_protocol,
            addresses: ProxyAddresses::Unix {
                source,
                destination,
            },
        });
    }

    let read_port = transport_protocol != ProxyTransportProtocol::Unspec;
    let port_length = if read_port { 4 } else { 0 };
    let address_length = if address_family == ProxyAddressFamily::Inet {
        8
    } else {
        32
    };
    ensure!(
        length >= port_length + address_length,
        InsufficientLengthSpecified {
            given: length,
            needs: port_length + address_length,
        },
    );
    ensure!(
        buf.remaining() >= port_length + address_length,
        UnexpectedEof,
    );

    let addresses = if address_family == ProxyAddressFamily::Inet {
        let mut data = [0u8; 4];
        buf.copy_to_slice(&mut data[..]);
        let source = Ipv4Addr::from(data);
        let source_port = if read_port { Some(buf.get_u16()) } else { None };

        buf.copy_to_slice(&mut data);
        let destination = Ipv4Addr::from(data);
        let destination_port = if read_port { Some(buf.get_u16()) } else { None };

        ProxyAddresses::Ipv4 {
            source: (source, source_port),
            destination: (destination, destination_port),
        }
    } else {
        let mut data = [0u8; 16];
        buf.copy_to_slice(&mut data);
        let source = Ipv6Addr::from(data);
        let source_port = if read_port { Some(buf.get_u16()) } else { None };

        buf.copy_to_slice(&mut data);
        let destination = Ipv6Addr::from(data);
        let destination_port = if read_port { Some(buf.get_u16()) } else { None };

        ProxyAddresses::Ipv6 {
            source: (source, source_port),
            destination: (destination, destination_port),
        }
    };

    if length > port_length + address_length {
        // TODO(Mariell Hoversholm): Implement TLVs
        buf.advance(length - (port_length + address_length));
    }

    Ok(super::ProxyHeader::Version2 {
        command,
        transport_protocol,
        addresses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProxyHeader;
    use bytes::{Bytes, BytesMut};
    use pretty_assertions::assert_eq;
    use rand::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_unspec() {
        assert_eq!(
            parse(&mut &[0u8; 16][..]),
            Ok(ProxyHeader::Version2 {
                command: ProxyCommand::Local,
                addresses: ProxyAddresses::Unspec,
                transport_protocol: ProxyTransportProtocol::Unspec,
            }),
        );

        let mut prefix = BytesMut::from(&[1u8][..]);
        prefix.reserve(16);
        prefix.extend_from_slice(&[0u8; 16][..]);
        assert_eq!(
            parse(&mut prefix),
            Ok(ProxyHeader::Version2 {
                command: ProxyCommand::Proxy,
                addresses: ProxyAddresses::Unspec,
                transport_protocol: ProxyTransportProtocol::Unspec,
            }),
        );
    }

    #[test]
    fn test_ipv4() {
        assert_eq!(
            parse(
                &mut &[
                    // Proxy command
                    1u8,
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
            ),
            Ok(ProxyHeader::Version2 {
                command: ProxyCommand::Proxy,
                transport_protocol: ProxyTransportProtocol::Stream,
                addresses: ProxyAddresses::Ipv4 {
                    source: (Ipv4Addr::new(127, 0, 0, 1), Some(65535)),
                    destination: (Ipv4Addr::new(192, 168, 0, 1), Some(257)),
                },
            })
        );

        let mut data = Bytes::from_static(
            &[
                // Local command
                0u8,
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
        );
        assert_eq!(
            parse(&mut data),
            Ok(ProxyHeader::Version2 {
                command: ProxyCommand::Local,
                transport_protocol: ProxyTransportProtocol::Datagram,
                addresses: ProxyAddresses::Ipv4 {
                    source: (Ipv4Addr::new(0, 0, 0, 0), Some(0)),
                    destination: (Ipv4Addr::new(255, 255, 255, 255), Some(255 << 8)),
                },
            })
        );
        assert!(data.remaining() == 4); // Consume the entire header
    }

    #[test]
    fn test_ipv6() {
        assert_eq!(
            parse(
                &mut &[
                    // Proxy command
                    1u8,
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
                ][..]
            ),
            Ok(ProxyHeader::Version2 {
                command: ProxyCommand::Proxy,
                transport_protocol: ProxyTransportProtocol::Datagram,
                addresses: ProxyAddresses::Ipv6 {
                    source: (
                        Ipv6Addr::new(65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535),
                        Some(65535),
                    ),
                    destination: (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), Some(257)),
                },
            })
        );

        let mut data = Bytes::from_static(
            &[
                // Local command
                0u8,
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
        );
        assert_eq!(
            parse(&mut data),
            Ok(ProxyHeader::Version2 {
                command: ProxyCommand::Local,
                transport_protocol: ProxyTransportProtocol::Stream,
                addresses: ProxyAddresses::Ipv6 {
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
    }

    #[test]
    fn test_invalid_data() {
        let mut data = [0u8; 200];
        rand::thread_rng().fill_bytes(&mut data);
        data[0] = 99; // Make 100% sure it's invalid.
        assert!(parse(&mut &data[..]).is_err());

        assert_eq!(parse(&mut &[0][..]), Err(Error::UnexpectedEof));

        assert_eq!(
            parse(
                &mut &[
                    // Proxy command
                    1u8,
                    // Inet << 4 | Stream
                    (1 << 4) | 1,
                    // Length beyond this: 12
                    // 3 bytes is clearly too few if we expect 2 IPv4s and ports
                    0,
                    3,
                ][..]
            ),
            Err(Error::InsufficientLengthSpecified {
                given: 3,
                needs: 4 * 2 + 2 * 2,
            }),
        );
    }
}
