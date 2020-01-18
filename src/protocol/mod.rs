pub mod binary;
pub mod version1;

use crate::error::*;
use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr as _,
};

/// The PROXY header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyHeader {
    Version1 {
        /// If this is Unspec, all the other values are zeroed. In any other
        /// case, the rest of the values have proper values.
        family: version1::ProxyAddressFamily,

        source: IpAddr,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
    },

    Version2 {
        command: binary::ProxyCommand,
        transport_protocol: binary::ProxyTransportProtocol,
        address: binary::ProxyAddress,
        source_port: Option<u16>,
        destination_port: Option<u16>,
    },
}

/// The possible versions of the proxy.
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProxyVersion {
    /// The human readable initial version. This is no longer the newest, but
    /// should be possible to both write and read nonetheless.
    Version1,

    /// The first binary version. This is the current version as of 2020-10-14.
    Version2,
}

impl ProxyHeader {
    pub fn encode(self) -> Result<BytesMut, EncodingError> {
        match self {
            Self::Version1 {
                family,
                source,
                destination,
                source_port,
                destination_port,
            } => Self::encode_v1(family, source, destination, source_port, destination_port),
            Self::Version2 {
                command,
                transport_protocol,
                address,
                source_port,
                destination_port,
            } => Self::encode_v2(
                command,
                transport_protocol,
                address,
                source_port,
                destination_port,
            ),
        }
    }

    #[allow(clippy::op_ref)]
    pub fn decode(buf: &mut Bytes) -> Result<Self, DecodingError> {
        if buf.remaining() < 13 {
            return Err(DecodingError::BufferSmall(13));
        }

        if &buf[..12] == &binary::CONNECTION_PREFIX[..] {
            return Self::decode_binary(buf);
        } else if &buf[..6] == &version1::CONNECTION_PREFIX[..] {
            return Self::decode_v1(buf);
        }

        Err(DecodingError::NotProxyHeader)
    }

    fn decode_binary(buf: &mut Bytes) -> Result<Self, DecodingError> {
        // Absolute minimum is 16 bytes.
        if buf.remaining() < 16 {
            return Err(DecodingError::BufferSmall(16));
        }

        // The 12 first bytes were correct, so let's ignore them.
        buf.advance(12);

        let command_and_version = buf.get_u8();

        let command = binary::ProxyCommand::read_command_binary(command_and_version)
            .ok_or(BinaryParsingError::InvalidCommand(command_and_version >> 4))?;
        if command == binary::ProxyCommand::Local {
            buf.advance(1);
            let data_length = buf.get_u16() as usize;
            if buf.remaining() < data_length {
                return Err(DecodingError::BufferSmall(data_length));
            }
            buf.advance(data_length);

            // All the information should be provided through the socket.
            // This is the same proxy connecting to itself, so let's do as the
            // spec says and just drop it here.
            return Ok(Self::Version2 {
                command,
                transport_protocol: binary::ProxyTransportProtocol::Unspec,
                address: binary::ProxyAddress::Unspec,
                source_port: None,
                destination_port: None,
            });
        }

        let _proxy_version = match (command_and_version & 0b1111_0000) >> 4 {
            0x2 => ProxyVersion::Version2,
            unknown => return Err(BinaryParsingError::InvalidVersion(unknown).into()),
        };

        let transport_protocol_and_address_family = buf.get_u8();
        let data_length = buf.get_u16() as usize;

        let transport_protocol = binary::ProxyTransportProtocol::read_protocol_binary(
            transport_protocol_and_address_family,
        )
        .ok_or(BinaryParsingError::InvalidTransportProtocol(
            transport_protocol_and_address_family >> 4,
        ))?;
        let address_family =
            binary::ProxyAddressFamily::read_family_binary(transport_protocol_and_address_family)
                .ok_or(BinaryParsingError::InvalidAddressFamily(
                transport_protocol_and_address_family & 0b0000_1111,
            ))?;

        if buf.remaining() < data_length {
            return Err(DecodingError::BufferSmall(data_length));
        }

        let address = binary::ProxyAddress::read_addresses(address_family, buf)?;

        let source_port = if buf.remaining() >= 2 {
            Some(buf.get_u16())
        } else {
            None
        };
        let destination_port = if buf.remaining() >= 2 {
            Some(buf.get_u16())
        } else {
            None
        };

        Ok(Self::Version2 {
            command,
            transport_protocol,
            address,
            source_port,
            destination_port,
        })
    }

    #[allow(clippy::op_ref)]
    fn decode_v1(buf: &mut Bytes) -> Result<Self, DecodingError> {
        let start_remaining = buf.remaining();
        // Absolute minimum is 15 bytes in: `PROXY UNKNOWN\r\n`.
        if start_remaining < 15 {
            return Err(DecodingError::BufferSmall(15));
        }

        if &buf.bytes()[..15] == &version1::UNKNOWN_PROXY_HEADER[..] {
            buf.advance(15);
            return Ok(Self::Version1 {
                family: version1::ProxyAddressFamily::Unknown,
                source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                source_port: 0,
                destination_port: 0,
            });
        }

        // The first 6 bytes were correct, let's skip them.
        buf.advance(6);

        let four = [buf.get_u8(), buf.get_u8(), buf.get_u8(), buf.get_u8()];
        let family = if four == version1::TCP4 {
            version1::ProxyAddressFamily::IPv4
        } else if four == version1::TCP6 {
            version1::ProxyAddressFamily::IPv6
        } else if four == version1::UNKNOWN[..4] {
            buf.advance(3);
            version1::ProxyAddressFamily::Unknown
        } else {
            return Err(Version1ParsingError::InvalidAddressFamily.into());
        };

        if buf.remaining() < 2 {
            return Err(DecodingError::BufferSmall(2));
        }
        if &buf.bytes()[..2] == &version1::CRLF[..] {
            buf.advance(2);
            return Ok(Self::Version1 {
                family,
                source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                source_port: 0,
                destination_port: 0,
            });
        }

        let space = buf.get_u8();
        if space != b' ' {
            return Err(Version1ParsingError::ExpectedSpace(
                space,
                start_remaining - buf.remaining(),
            )
            .into());
        }

        let mut source = Vec::with_capacity(family.min_length());
        let mut c = buf.get_u8();
        while c != b' ' {
            source.push(c);
            c = buf.get_u8();
        }
        let source = String::from_utf8(source)?;
        let source = match IpAddr::from_str(&source) {
            Ok(s) => s,
            Err(e) => return Err(DecodingError::AddrParse(e, source)),
        };

        // No space check; the loop should have eaten the space.

        let mut dest = Vec::with_capacity(family.min_length());
        let mut c = buf.get_u8();
        while c != b' ' && c != b'\r' {
            dest.push(c);
            c = buf.get_u8();
        }
        let dest = String::from_utf8(dest)?;
        let dest = match IpAddr::from_str(&dest) {
            Ok(s) => s,
            Err(e) => return Err(DecodingError::AddrParse(e, dest)),
        };

        if dest.is_ipv4() != source.is_ipv4() {
            return Err(Version1ParsingError::UnequalAddressFamilies.into());
        }

        if buf.remaining() < 1 {
            return Err(DecodingError::BufferSmall(1));
        }
        // The last loop should have eaten the b'\r' or the b' '.
        if &buf.bytes()[..1] == &[b'\n'] {
            buf.advance(1);
            return Ok(Self::Version1 {
                family,
                source,
                destination: dest,
                source_port: 0,
                destination_port: 0,
            });
        }

        // No space check; the loop should have eaten the space.

        let mut source_port = Vec::with_capacity(family.min_length());
        let mut c = buf.get_u8();
        while c != b' ' {
            source_port.push(c);
            c = buf.get_u8();
        }
        let source_port = String::from_utf8(source_port)?;
        let source_port: u16 = source_port.parse()?;

        let mut dest_port = Vec::with_capacity(family.min_length());
        let mut c = buf.get_u8();
        while c != b'\r' {
            dest_port.push(c);
            c = buf.get_u8();
        }
        let dest_port = String::from_utf8(dest_port)?;
        let dest_port: u16 = dest_port.parse()?;

        if buf.remaining() < 1 {
            return Err(DecodingError::BufferSmall(1));
        }
        // The last loop should have eaten the b'\r'.
        if &buf.bytes()[..1] != &[b'\n'] {
            buf.advance(1);
            return Err(Version1ParsingError::ExpectedCRLF.into());
        }

        Ok(Self::Version1 {
            family,
            source,
            destination: dest,
            source_port,
            destination_port: dest_port,
        })
    }

    fn encode_v1(
        family: version1::ProxyAddressFamily,
        source: IpAddr,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
    ) -> Result<BytesMut, EncodingError> {
        if family == version1::ProxyAddressFamily::Unknown {
            return Ok(BytesMut::from(&version1::UNKNOWN_PROXY_HEADER[..]));
        }

        let family_formatted = match family {
            version1::ProxyAddressFamily::Unknown => version1::UNKNOWN_STR,
            version1::ProxyAddressFamily::IPv4 => version1::TCP4_STR,
            version1::ProxyAddressFamily::IPv6 => version1::TCP6_STR,
        };

        let equal_type = source.is_ipv4() == destination.is_ipv4();
        let source = if equal_type {
            source
        } else {
            match source {
                IpAddr::V4(addr) => IpAddr::V6(addr.to_ipv6_mapped()),
                IpAddr::V6(addr) => IpAddr::V6(addr),
            }
        };
        let destination = if equal_type {
            destination
        } else {
            match destination {
                IpAddr::V4(addr) => IpAddr::V6(addr.to_ipv6_mapped()),
                IpAddr::V6(addr) => IpAddr::V6(addr),
            }
        };

        Ok(BytesMut::from(
            format!(
                "PROXY {} {} {} {} {}\r\n",
                family_formatted, source, destination, source_port, destination_port
            )
            .as_str(),
        ))
    }

    fn encode_v2(
        command: binary::ProxyCommand,
        transport_protocol: binary::ProxyTransportProtocol,
        address: binary::ProxyAddress,
        source_port: Option<u16>,
        destination_port: Option<u16>,
    ) -> Result<BytesMut, EncodingError> {
        if source_port.is_none() && destination_port.is_some() {
            return Err(EncodingError::DestinationPortButNoSource);
        }

        let address_bytes_length = match &address {
            binary::ProxyAddress::Unspec => 0,
            binary::ProxyAddress::IpV4 { .. } => {
                4 + 4
                    + source_port.map(|_| 2).unwrap_or(0)
                    + destination_port.map(|_| 2).unwrap_or(0)
            }
            binary::ProxyAddress::IpV6 { .. } => {
                8 + 8
                    + source_port.map(|_| 2).unwrap_or(0)
                    + destination_port.map(|_| 2).unwrap_or(0)
            }
            binary::ProxyAddress::UnixSocket { .. } => 108 + 108,
        };

        let mut buf = BytesMut::with_capacity(16 + address_bytes_length);

        buf.put_slice(&binary::CONNECTION_PREFIX[..]);
        buf.put_u8((0x2 << 4) | command as u8);
        buf.put_u8(((address.family() as u8) << 4) | transport_protocol as u8);
        buf.put_u16(address_bytes_length as u16);

        address.write(&mut buf);

        match (source_port, destination_port) {
            (Some(src), Some(dest)) => {
                buf.put_u16(src);
                buf.put_u16(dest);
            }
            (Some(src), None) => buf.put_u16(src),
            (_, _) => (),
        }

        Ok(buf)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::error::*;
    use bytes::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_v1() {
        let proxy = b"PROXY UNKNOWN\r\n";
        let mut bytes = Bytes::from(&proxy[..]);
        let header = match ProxyHeader::decode(&mut bytes) {
            Ok(h) => h,
            Err(e) => panic!("unknown proxy not recognised 1: {:?} / {}", e, e),
        };
        assert_eq!(
            header,
            ProxyHeader::Version1 {
                family: version1::ProxyAddressFamily::Unknown,
                source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                source_port: 0,
                destination_port: 0,
            }
        );
        let encoded = ProxyHeader::Version1 {
            family: version1::ProxyAddressFamily::Unknown,
            source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            source_port: 0,
            destination_port: 0,
        }
        .encode()
        .unwrap();
        assert_eq!(encoded.bytes(), &proxy[..]);

        let proxy = b"PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let mut bytes = Bytes::from(&proxy[..]);
        let header = match ProxyHeader::decode(&mut bytes) {
            Ok(h) => h,
            Err(e) => panic!("unknown proxy not recognised 2: {:?} / {}", e, e),
        };
        let max = u16::max_value();
        assert_eq!(
            header,
            ProxyHeader::Version1 {
                family: version1::ProxyAddressFamily::Unknown,
                source: IpAddr::V6(Ipv6Addr::new(max, max, max, max, max, max, max, max)),
                destination: IpAddr::V6(Ipv6Addr::new(max, max, max, max, max, max, max, max)),
                source_port: max,
                destination_port: max,
            }
        );

        let proxy = b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";
        let mut bytes = Bytes::from(&proxy[..]);
        let header = match ProxyHeader::decode(&mut bytes) {
            Ok(h) => h,
            Err(e) => panic!("unknown proxy not recognised 3: {:?} / {}", e, e),
        };
        let max = u16::max_value();
        assert_eq!(
            header,
            ProxyHeader::Version1 {
                family: version1::ProxyAddressFamily::IPv4,
                source: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                destination: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                source_port: max,
                destination_port: max,
            }
        );
        let encoded = ProxyHeader::Version1 {
            family: version1::ProxyAddressFamily::IPv4,
            source: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            destination: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            source_port: max,
            destination_port: max,
        }
        .encode()
        .unwrap();
        assert_eq!(encoded.bytes(), &proxy[..]);
    }

    #[test]
    fn test_v2() {
        let mut bytes = Bytes::from(
            &[
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
                (0x2u8 << 4) | 1,
                0x11,
                0x00,
                8,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
            ][..],
        );
        let header = ProxyHeader::decode(&mut bytes).unwrap();
        assert_eq!(
            header,
            ProxyHeader::Version2 {
                command: binary::ProxyCommand::Proxy,
                transport_protocol: binary::ProxyTransportProtocol::Stream,
                address: binary::ProxyAddress::IpV4 {
                    source: [0xFF, 0xFF, 0xFF, 0xFF],
                    destination: [0xFF, 0xFF, 0xFF, 0xFF],
                },
                source_port: None,
                destination_port: None,
            }
        );
        let encoded = ProxyHeader::Version2 {
            command: binary::ProxyCommand::Proxy,
            transport_protocol: binary::ProxyTransportProtocol::Stream,
            address: binary::ProxyAddress::IpV4 {
                source: [0xFF, 0xFF, 0xFF, 0xFF],
                destination: [0xFF, 0xFF, 0xFF, 0xFF],
            },
            source_port: None,
            destination_port: None,
        }
        .encode()
        .unwrap();
        assert_eq!(
            encoded.bytes(),
            &[
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
                (0x2u8 << 4) | 1,
                0x11,
                0x00,
                8,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
            ][..]
        );
    }
}
