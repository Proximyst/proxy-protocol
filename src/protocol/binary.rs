use crate::error::*;
use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use std::net::IpAddr;

/// The 12 bytes required to notify of being a V2 binary PROXY protocol
/// connection.
///
/// Excerpt from the specification:
///
/// > The binary header format starts with a constant 12 bytes block containing the
/// > protocol signature :
/// >
/// >    `\x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A`
pub const CONNECTION_PREFIX: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

#[allow(dead_code)] // Compiler bug - https://github.com/rust-lang/rust/issues/64362
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(u8)]
pub enum ProxyCommand {
    Local = 0x0,
    Proxy = 0x1,
}

#[allow(dead_code)] // Compiler bug - https://github.com/rust-lang/rust/issues/64362
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(u8)]
pub enum ProxyTransportProtocol {
    Unspec = 0x0,
    Stream = 0x1,
    DGram = 0x2,
}

#[allow(dead_code)] // Compiler bug - https://github.com/rust-lang/rust/issues/64362
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum ProxyAddress {
    Unspec,
    IpV4 {
        source: [u8; 4],
        destination: [u8; 4],
    },
    IpV6 {
        source: [u8; 16],
        destination: [u8; 16],
    },
    UnixSocket {
        source: Vec<u8>,
        destination: Vec<u8>,
    },
}

impl ProxyAddress {
    pub fn from_ipaddr(first: IpAddr, second: IpAddr) -> Self {
        let ipv4 = first.is_ipv4() && second.is_ipv4();
        if ipv4 {
            Self::IpV4 {
                source: match first {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(v6) => v6
                        .to_ipv4()
                        .expect("cannot both be ipv4 but not match ipv4"),
                }
                .octets(),
                destination: match second {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(v6) => v6
                        .to_ipv4()
                        .expect("cannot both be ipv4 but not match ipv4"),
                }
                .octets(),
            }
        } else {
            Self::IpV6 {
                source: match first {
                    IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                    IpAddr::V6(v6) => v6,
                }
                .octets(),
                destination: match second {
                    IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                    IpAddr::V6(v6) => v6,
                }
                .octets(),
            }
        }
    }

    pub fn read_addresses(
        family: ProxyAddressFamily,
        bytes: &mut Bytes,
    ) -> Result<Self, BinaryParsingError> {
        match family {
            ProxyAddressFamily::Unspec => Ok(Self::Unspec),
            ProxyAddressFamily::InetV4 => Self::read_ipv4(bytes),
            ProxyAddressFamily::InetV6 => Self::read_ipv6(bytes),
            ProxyAddressFamily::UnixSocket => Self::read_unix_socket(bytes),
        }
    }

    pub fn family(&self) -> ProxyAddressFamily {
        match self {
            Self::Unspec => ProxyAddressFamily::Unspec,
            Self::IpV4 { .. } => ProxyAddressFamily::InetV4,
            Self::IpV6 { .. } => ProxyAddressFamily::InetV6,
            Self::UnixSocket { .. } => ProxyAddressFamily::UnixSocket,
        }
    }

    pub fn write(&self, buf: &mut BytesMut) {
        match self {
            Self::Unspec => (),
            Self::IpV4 {
                source,
                destination,
            } => {
                buf.put_slice(&source[..]);
                buf.put_slice(&destination[..]);
            }
            Self::IpV6 {
                source,
                destination,
            } => {
                buf.put_slice(&source[..]);
                buf.put_slice(&destination[..]);
            }
            Self::UnixSocket {
                source,
                destination,
            } => {
                buf.put_slice(&source);
                buf.put_slice(&destination);
            }
        }
    }

    fn read_ipv4(bytes: &mut Bytes) -> Result<Self, BinaryParsingError> {
        if bytes.remaining() < 8 {
            return Err(BinaryParsingError::BufferSmall(8));
        }
        // 8 bytes available; the 4 first are the source, 4 last are destination.

        let source = [
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
        ];
        let dest = [
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
        ];

        Ok(Self::IpV4 {
            source,
            destination: dest,
        })
    }

    fn read_ipv6(bytes: &mut Bytes) -> Result<Self, BinaryParsingError> {
        if bytes.remaining() < 32 {
            return Err(BinaryParsingError::BufferSmall(32));
        }
        // 32 bytes available; the 16 first are the source, 16 last are destination.

        let source = [
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
        ];
        let dest = [
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
        ];

        Ok(Self::IpV6 {
            source,
            destination: dest,
        })
    }

    fn read_unix_socket(bytes: &mut Bytes) -> Result<Self, BinaryParsingError> {
        if bytes.remaining() < 216 {
            return Err(BinaryParsingError::BufferSmall(216));
        }
        // 216 bytes available; the 108 first are the source, 108 last are destination.

        let mut source = vec![0; 108];
        let mut dest = vec![0; 108];

        bytes.copy_to_slice(&mut source);
        bytes.copy_to_slice(&mut dest);

        Ok(Self::UnixSocket {
            source,
            destination: dest,
        })
    }
}

#[allow(dead_code)] // Compiler bug - https://github.com/rust-lang/rust/issues/64362
#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProxyAddressFamily {
    Unspec = 0x0,
    InetV4 = 0x1,
    InetV6 = 0x2,
    UnixSocket = 0x3,
}

impl ProxyCommand {
    pub fn read_command_binary(byte: u8) -> Option<Self> {
        // Excerpt from the specification:
        //
        // The lowest four bits represents the command :
        //   - \x0 : LOCAL : the connection was established on purpose by the proxy
        //     without being relayed. The connection endpoints are the sender and the
        //     receiver. Such connections exist when the proxy sends health-checks to the
        //     server. The receiver must accept this connection as valid and must use the
        //     real connection endpoints and discard the protocol block including the
        //     family which is ignored.
        //
        //   - \x1 : PROXY : the connection was established on behalf of another node,
        //     and reflects the original connection endpoints. The receiver must then use
        //     the information provided in the protocol block to get original the address.
        //
        //   - other values are unassigned and must not be emitted by senders. Receivers
        //     must drop connections presenting unexpected values here.

        Some(match byte & 0b0000_1111 {
            0x0 => Self::Local,
            0x1 => Self::Proxy,
            _ => return None,
        })
    }
}

impl ProxyAddressFamily {
    pub fn read_family_binary(byte: u8) -> Option<Self> {
        // Excerpt from the specification:
        //
        // The 14th byte contains the transport protocol and address family. The highest 4
        // bits contain the address family, the lowest 4 bits contain the protocol.
        //
        // The address family maps to the original socket family without necessarily
        // matching the values internally used by the system. It may be one of :
        //
        //   - 0x0 : AF_UNSPEC : the connection is forwarded for an unknown, unspecified
        //     or unsupported protocol. The sender should use this family when sending
        //     LOCAL commands or when dealing with unsupported protocol families. The
        //     receiver is free to accept the connection anyway and use the real endpoint
        //     addresses or to reject it. The receiver should ignore address information.
        //
        //   - 0x1 : AF_INET : the forwarded connection uses the AF_INET address family
        //     (IPv4). The addresses are exactly 4 bytes each in network byte order,
        //     followed by transport protocol information (typically ports).
        //
        //   - 0x2 : AF_INET6 : the forwarded connection uses the AF_INET6 address family
        //     (IPv6). The addresses are exactly 16 bytes each in network byte order,
        //     followed by transport protocol information (typically ports).
        //
        //   - 0x3 : AF_UNIX : the forwarded connection uses the AF_UNIX address family
        //     (UNIX). The addresses are exactly 108 bytes each.
        //
        //   - other values are unspecified and must not be emitted in version 2 of this
        //     protocol and must be rejected as invalid by receivers.

        Some(match byte >> 4 {
            0x0 => Self::Unspec,
            0x1 => Self::InetV4,
            0x2 => Self::InetV6,
            0x3 => Self::UnixSocket,
            _ => return None,
        })
    }
}

impl ProxyTransportProtocol {
    pub fn read_protocol_binary(byte: u8) -> Option<Self> {
        // Excerpt from the specification:
        //
        // The 14th byte contains the transport protocol and address family. The highest 4
        // bits contain the address family, the lowest 4 bits contain the protocol.
        //
        // The transport protocol is specified in the lowest 4 bits of the 14th byte :
        //
        //   - 0x0 : UNSPEC : the connection is forwarded for an unknown, unspecified
        //     or unsupported protocol. The sender should use this family when sending
        //     LOCAL commands or when dealing with unsupported protocol families. The
        //     receiver is free to accept the connection anyway and use the real endpoint
        //     addresses or to reject it. The receiver should ignore address information.
        //
        //   - 0x1 : STREAM : the forwarded connection uses a SOCK_STREAM protocol (eg:
        //     TCP or UNIX_STREAM). When used with AF_INET/AF_INET6 (TCP), the addresses
        //     are followed by the source and destination ports represented on 2 bytes
        //     each in network byte order.
        //
        //   - 0x2 : DGRAM : the forwarded connection uses a SOCK_DGRAM protocol (eg:
        //     UDP or UNIX_DGRAM). When used with AF_INET/AF_INET6 (UDP), the addresses
        //     are followed by the source and destination ports represented on 2 bytes
        //     each in network byte order.
        //
        //   - other values are unspecified and must not be emitted in version 2 of this
        //     protocol and must be rejected as invalid by receivers.

        Some(match byte & 0b0000_1111 {
            0x0 => Self::Unspec,
            0x1 => Self::Stream,
            0x2 => Self::DGram,
            _ => return None,
        })
    }
}
