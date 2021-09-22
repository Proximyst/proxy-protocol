use bytes::{Buf, BufMut as _, BytesMut};
use snafu::{ensure, Snafu};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

#[derive(Debug, Snafu)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum ParseError {
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
        source: SocketAddrV4,
        destination: SocketAddrV4,
    },
    Ipv6 {
        source: SocketAddrV6,
        destination: SocketAddrV6,
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

pub(crate) fn parse(buf: &mut impl Buf) -> Result<super::ProxyHeader, ParseError> {
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

    let port_length = 4;
    let address_length = match address_family {
        ProxyAddressFamily::Inet => 8,
        ProxyAddressFamily::Inet6 => 32,
        _ => unreachable!(),
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

        buf.copy_to_slice(&mut data);
        let destination = Ipv4Addr::from(data);

        let source_port = buf.get_u16();
        let destination_port = buf.get_u16();

        ProxyAddresses::Ipv4 {
            source: SocketAddrV4::new(source, source_port),
            destination: SocketAddrV4::new(destination, destination_port),
        }
    } else {
        let mut data = [0u8; 16];
        buf.copy_to_slice(&mut data);
        let source = Ipv6Addr::from(data);

        buf.copy_to_slice(&mut data);
        let destination = Ipv6Addr::from(data);

        let source_port = buf.get_u16();
        let destination_port = buf.get_u16();

        ProxyAddresses::Ipv6 {
            source: SocketAddrV6::new(source, source_port, 0, 0),
            destination: SocketAddrV6::new(destination, destination_port, 0, 0),
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

pub(crate) fn encode(
    command: ProxyCommand,
    transport_protocol: ProxyTransportProtocol,
    addresses: ProxyAddresses,
) -> BytesMut {
    // > struct proxy_hdr_v2 {
    // >     uint8_t sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    // >     uint8_t ver_cmd;  /* protocol version and command */
    // >     uint8_t fam;      /* protocol family and address */
    // >     uint16_t len;     /* number of following bytes part of the header */
    // > };
    const SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];

    // > The next byte (the 13th one) is the protocol version and command.
    // >
    // > The highest four bits contains the version. As of this specification, it must
    // > always be sent as \x2 and the receiver must only accept this value.
    // >
    // > The lowest four bits represents the command :
    // >   - \x0 : LOCAL : the connection was established on purpose by the proxy
    // >     without being relayed. The connection endpoints are the sender and the
    // >     receiver. Such connections exist when the proxy sends health-checks to the
    // >     server. The receiver must accept this connection as valid and must use the
    // >     real connection endpoints and discard the protocol block including the
    // >     family which is ignored.
    // >
    // >   - \x1 : PROXY : the connection was established on behalf of another node,
    // >     and reflects the original connection endpoints. The receiver must then use
    // >     the information provided in the protocol block to get original the address.
    // >
    // >   - other values are unassigned and must not be emitted by senders. Receivers
    // >     must drop connections presenting unexpected values here.
    let ver_cmd = (2 << 4)
        | match command {
            ProxyCommand::Local => 0,
            ProxyCommand::Proxy => 1,
        };

    // > The 14th byte contains the transport protocol and address family. The highest 4
    // > bits contain the address family, the lowest 4 bits contain the protocol.
    // >
    // > The address family maps to the original socket family without necessarily
    // > matching the values internally used by the system. It may be one of :
    // >
    // >   - 0x0 : AF_UNSPEC : the connection is forwarded for an unknown, unspecified
    // >     or unsupported protocol. The sender should use this family when sending
    // >     LOCAL commands or when dealing with unsupported protocol families. The
    // >     receiver is free to accept the connection anyway and use the real endpoint
    // >     addresses or to reject it. The receiver should ignore address information.
    // >
    // >   - 0x1 : AF_INET : the forwarded connection uses the AF_INET address family
    // >     (IPv4). The addresses are exactly 4 bytes each in network byte order,
    // >     followed by transport protocol information (typically ports).
    // >
    // >   - 0x2 : AF_INET6 : the forwarded connection uses the AF_INET6 address family
    // >     (IPv6). The addresses are exactly 16 bytes each in network byte order,
    // >     followed by transport protocol information (typically ports).
    // >
    // >   - 0x3 : AF_UNIX : the forwarded connection uses the AF_UNIX address family
    // >     (UNIX). The addresses are exactly 108 bytes each.
    // >
    // >   - other values are unspecified and must not be emitted in version 2 of this
    // >     protocol and must be rejected as invalid by receivers.
    // >
    // > The transport protocol is specified in the lowest 4 bits of the 14th byte :
    // >
    // >   - 0x0 : UNSPEC : the connection is forwarded for an unknown, unspecified
    // >     or unsupported protocol. The sender should use this family when sending
    // >     LOCAL commands or when dealing with unsupported protocol families. The
    // >     receiver is free to accept the connection anyway and use the real endpoint
    // >     addresses or to reject it. The receiver should ignore address information.
    // >
    // >   - 0x1 : STREAM : the forwarded connection uses a SOCK_STREAM protocol (eg:
    // >     TCP or UNIX_STREAM). When used with AF_INET/AF_INET6 (TCP), the addresses
    // >     are followed by the source and destination ports represented on 2 bytes
    // >     each in network byte order.
    // >
    // >   - 0x2 : DGRAM : the forwarded connection uses a SOCK_DGRAM protocol (eg:
    // >     UDP or UNIX_DGRAM). When used with AF_INET/AF_INET6 (UDP), the addresses
    // >     are followed by the source and destination ports represented on 2 bytes
    // >     each in network byte order.
    // >
    // >   - other values are unspecified and must not be emitted in version 2 of this
    // >     protocol and must be rejected as invalid by receivers.
    let fam = (match addresses {
        ProxyAddresses::Unspec => 0,
        ProxyAddresses::Ipv4 { .. } => 1,
        ProxyAddresses::Ipv6 { .. } => 2,
        ProxyAddresses::Unix { .. } => 3,
    } << 4)
        | match transport_protocol {
            ProxyTransportProtocol::Unspec => 0,
            ProxyTransportProtocol::Stream => 1,
            ProxyTransportProtocol::Datagram => 2,
        };

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
    let len = match addresses {
        ProxyAddresses::Unspec => 0,
        ProxyAddresses::Unix { .. } => {
            108 + 108
        }
        ProxyAddresses::Ipv4 { .. } => {
            4 + 4 + 2 + 2
        }
        ProxyAddresses::Ipv6 { .. } => {
            16 + 16 + 2 + 2
        }
    };

    let mut buf = BytesMut::with_capacity(16 + len);
    buf.put_slice(&SIG[..]);
    buf.put_slice(&[ver_cmd, fam][..]);
    buf.put_u16(len as u16);

    match addresses {
        ProxyAddresses::Unspec => (),
        ProxyAddresses::Unix {
            source,
            destination,
        } => {
            buf.put_slice(&source[..]);
            buf.put_slice(&destination[..]);
        }
        ProxyAddresses::Ipv4 {
            source,
            destination,
        } => {
            buf.put_slice(&source.ip().octets()[..]);
            buf.put_slice(&destination.ip().octets()[..]);
            buf.put_u16(source.port());
            buf.put_u16(destination.port());
        }
        ProxyAddresses::Ipv6 {
            source,
            destination,
        } => {
            buf.put_slice(&source.ip().octets()[..]);
            buf.put_slice(&destination.ip().octets()[..]);
            buf.put_u16(source.port());
            buf.put_u16(destination.port());
        }
    }

    buf
}

#[cfg(test)]
mod parse_tests {
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
                    // Destination IP
                    192,
                    168,
                    0,
                    1,
                    // Source port
                    // 65535 = [255, 255]
                    255,
                    255,
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
                    source: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 65535),
                    destination: SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 257),
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
                // Destination IP
                255,
                255,
                255,
                255,
                // Source port
                0,
                0,
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
                    source: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0),
                    destination: SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), 255 << 8),
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
                    // Source port
                    // 65535 = [255, 255]
                    255,
                    255,
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
                    source: SocketAddrV6::new(
                        Ipv6Addr::new(65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535),
                        65535,
                        0,
                        0,
                    ),
                    destination: SocketAddrV6::new(
                        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                        257,
                        0,
                        0,
                    ),
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
                // Source port
                123,
                0,
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
                    source: SocketAddrV6::new(
                        Ipv6Addr::new(20828, 52, 21260, 65348, 4869, 28616, 13914, 14146),
                        31488,
                        0,
                        0,
                    ),
                    destination: SocketAddrV6::new(
                        Ipv6Addr::new(65535, 65535, 0, 0, 31611, 17733, 5397, 10794),
                        65535,
                        0,
                        0,
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

        assert_eq!(parse(&mut &[0][..]), Err(ParseError::UnexpectedEof));

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
            Err(ParseError::InsufficientLengthSpecified {
                given: 3,
                needs: 4 * 2 + 2 * 2,
            }),
        );
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
    use pretty_assertions::assert_eq;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];

    fn signed(buf: &[u8]) -> Bytes {
        let mut bytes = BytesMut::from(&SIG[..]);
        bytes.extend_from_slice(buf);
        bytes.freeze()
    }

    #[test]
    fn test_unspec() {
        assert_eq!(
            encode(
                ProxyCommand::Local,
                ProxyTransportProtocol::Unspec,
                ProxyAddresses::Unspec,
            ),
            signed(&[2 << 4, 0, 0, 0][..]),
        );

        assert_eq!(
            encode(
                ProxyCommand::Proxy,
                ProxyTransportProtocol::Unspec,
                ProxyAddresses::Unspec,
            ),
            signed(&[(2 << 4) | 1, 0, 0, 0][..]),
        );
        assert_eq!(
            encode(
                ProxyCommand::Proxy,
                ProxyTransportProtocol::Unspec,
                ProxyAddresses::Ipv4 {
                    source: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 65535),
                    destination: SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 9012),
                },
            ),
            signed(
                &[
                    (2 << 4) | 1,
                    1 << 4,
                    0,
                    12,
                    1,
                    2,
                    3,
                    4,
                    192,
                    168,
                    0,
                    1,
                    255,
                    255,
                    (9012u16 >> 8) as u8,
                    9012u16 as u8,
                ][..]
            ),
        );
    }

    #[test]
    fn test_ipv4() {
        assert_eq!(
            encode(
                ProxyCommand::Proxy,
                ProxyTransportProtocol::Stream,
                ProxyAddresses::Ipv4 {
                    source: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 65535),
                    destination: SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 9012),
                },
            ),
            signed(
                &[
                    (2 << 4) | 1,
                    (1 << 4) | 1,
                    0,
                    12,
                    1,
                    2,
                    3,
                    4,
                    192,
                    168,
                    0,
                    1,
                    255,
                    255,
                    (9012u16 >> 8) as u8,
                    9012u16 as u8,
                ][..]
            ),
        );
        assert_eq!(
            encode(
                ProxyCommand::Local,
                ProxyTransportProtocol::Datagram,
                ProxyAddresses::Ipv4 {
                    source: SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), 324),
                    destination: SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 2187),
                },
            ),
            signed(
                &[
                    2 << 4,
                    (1 << 4) | 2,
                    0,
                    12,
                    255,
                    255,
                    255,
                    255,
                    192,
                    168,
                    0,
                    1,
                    (324u16 >> 8) as u8,
                    324u16 as u8,
                    (2187 >> 8) as u8,
                    2187u16 as u8,
                ][..]
            ),
        );
    }

    #[test]
    fn test_ipv6() {
        assert_eq!(
            encode(
                ProxyCommand::Local,
                ProxyTransportProtocol::Datagram,
                ProxyAddresses::Ipv6 {
                    source: SocketAddrV6::new(
                        Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
                        8192,
                        0,
                        0,
                    ),
                    destination: SocketAddrV6::new(
                        Ipv6Addr::new(65535, 65535, 32767, 32766, 111, 222, 333, 444),
                        0,
                        0,
                        0,
                    ),
                }
            ),
            signed(
                &[
                    2 << 4,
                    (2 << 4) | 2,
                    0,
                    36,
                    0,
                    1,
                    0,
                    2,
                    0,
                    3,
                    0,
                    4,
                    0,
                    5,
                    0,
                    6,
                    0,
                    7,
                    0,
                    8,
                    255,
                    255,
                    255,
                    255,
                    (32767u16 >> 8) as u8,
                    32767u16 as u8,
                    (32766u16 >> 8) as u8,
                    32766u16 as u8,
                    0,
                    111,
                    0,
                    222,
                    (333u16 >> 8) as u8,
                    333u16 as u8,
                    (444u16 >> 8) as u8,
                    444u16 as u8,
                    (8192u16 >> 8) as u8,
                    8192u16 as u8,
                    0,
                    0,
                ][..]
            ),
        );
    }
}
