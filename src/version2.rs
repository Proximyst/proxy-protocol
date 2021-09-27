use bytes::{Buf, BufMut as _, BytesMut};
use snafu::{ensure, Snafu};
use std::convert::TryInto;
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

    #[snafu(display("invalid length specified: {}, causes overflow", given))]
    LengthOverflow { given: usize },

    #[snafu(display("invalid TLV type id specified: {}", type_id))]
    InvalidTlvTypeId { type_id: u8 },

    #[snafu(display("invalid UTF-8: {:?}", bytes))]
    InvalidUtf8 { bytes: Vec<u8> },

    #[snafu(display("invalid ASCII: {:?}", bytes))]
    InvalidAscii { bytes: Vec<u8> },

    #[snafu(display("trailing data: {:?}", len))]
    TrailingData { len: usize },
}

#[derive(Debug, Snafu)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum EncodeError {
    #[snafu(display("value is too large to encode"))]
    ValueTooLarge,
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

trait Tlv: Sized {
    /// Identifies the type
    fn type_id(&self) -> u8;

    /// The byte size of the value if encoded, or None if too big
    fn value_len(&self) -> Result<u16, EncodeError>;

    /// Write the value to the provided buffer
    fn encode_value(&self, buf: &mut BytesMut) -> Result<(), EncodeError>;

    fn encoded_len(&self) -> Result<u16, EncodeError> {
        self.value_len()?
            .checked_add(3)
            .ok_or(EncodeError::ValueTooLarge)
    }

    fn encode(&self, buf: &mut BytesMut) -> Result<(), EncodeError> {
        let vlen = self.value_len()?;
        if vlen
            .checked_add(3)
            .map_or(true, |tlv_len| buf.remaining_mut() < tlv_len.into())
        {
            return Err(EncodeError::ValueTooLarge);
        }
        buf.put_u8(self.type_id());
        buf.put_u16(vlen);
        self.encode_value(buf)
    }

    // API note:
    // We have to pass the len instead of using a view.
    // Buf doesn't have a good view / subslice abstraction
    // unlike plain slices or even the Bytes implementation
    // IMHO (@g2p) it would be better for parse to receive a
    // slice or a concrete type.
    fn parse_parts(type_id: u8, len: u16, buf: &mut impl Buf) -> Result<Self, ParseError>;

    fn parse(buf: &mut impl Buf) -> Result<Self, ParseError> {
        if buf.remaining() < 3 {
            return Err(ParseError::UnexpectedEof);
        }
        let type_id = buf.get_u8();
        let vlen = buf.get_u16();
        let expected_rem = buf
            .remaining()
            .checked_sub(vlen.into())
            .ok_or(ParseError::UnexpectedEof)?;
        let r = Self::parse_parts(type_id, vlen, buf)?;
        // Assert, because it would be an internal error
        assert_eq!(buf.remaining(), expected_rem);
        Ok(r)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslClientFlags(u8);

impl SslClientFlags {
    pub fn is_ssl_or_tls(&self) -> bool {
        (self.0 & 1) == 1
    }

    pub fn client_authenticated_connection(&self) -> bool {
        (self.0 & 2) == 2
    }
    pub fn client_authenticated_session(&self) -> bool {
        (self.0 & 4) == 4
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslVerifyStatus(u32);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "always_exhaustive"), non_exhaustive)] // Extensions may be added
pub enum SslExtensionTlv {
    /// TLS or SSL version in ASCII
    Version(String),
    /// TLS or SSL cipher suite in ASCII, for example "ECDHE-RSA-AES128-GCM-SHA256"
    Cipher(String),
    /// TLS or SSL signature algorithm in ASCII
    SigAlg(String),
    /// TLS or SSL key algorithm in ASCII
    KeyAlg(String),
    /// With client authentication, the common name for the client certificate in UTF-8
    ClientCN(String),
}

impl SslExtensionTlv {
    fn as_str(&self) -> &str {
        match self {
            Self::Version(version) => version,
            Self::Cipher(cipher) => cipher,
            Self::SigAlg(sigalg) => sigalg,
            Self::KeyAlg(keyalg) => keyalg,
            Self::ClientCN(cn) => cn,
        }
    }
}

impl Tlv for SslExtensionTlv {
    fn type_id(&self) -> u8 {
        match self {
            Self::Version(_) => PP2_SUBTYPE_SSL_VERSION,
            Self::ClientCN(_) => PP2_SUBTYPE_SSL_CN,
            Self::Cipher(_) => PP2_SUBTYPE_SSL_CIPHER,
            Self::SigAlg(_) => PP2_SUBTYPE_SSL_SIG_ALG,
            Self::KeyAlg(_) => PP2_SUBTYPE_SSL_KEY_ALG,
        }
    }

    fn value_len(&self) -> Result<u16, EncodeError> {
        self.as_str()
            .len()
            .try_into()
            .map_err(|_| EncodeError::ValueTooLarge)
    }

    fn encode_value(&self, buf: &mut BytesMut) -> Result<(), EncodeError> {
        buf.put_slice(self.as_str().as_bytes());
        Ok(())
    }

    fn parse_parts(type_id: u8, len: u16, buf: &mut impl Buf) -> Result<Self, ParseError> {
        Ok(match type_id {
            PP2_SUBTYPE_SSL_VERSION => Self::Version(ascii_from_buf(buf, len)?),
            PP2_SUBTYPE_SSL_CIPHER => Self::Version(ascii_from_buf(buf, len)?),
            PP2_SUBTYPE_SSL_SIG_ALG => Self::Version(ascii_from_buf(buf, len)?),
            PP2_SUBTYPE_SSL_KEY_ALG => Self::Version(ascii_from_buf(buf, len)?),
            PP2_SUBTYPE_SSL_CN => Self::Version(str_from_buf(buf, len)?),
            _ => return Err(ParseError::InvalidTlvTypeId { type_id }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssl {
    client: SslClientFlags,
    verify: SslVerifyStatus,
    extensions: Vec<SslExtensionTlv>,
}

impl Ssl {
    fn parse(buf: &mut impl Buf, len: u16) -> Result<Self, ParseError> {
        if buf.remaining() < len.into() {
            return Err(ParseError::UnexpectedEof);
        }
        let mut ext_len = len
            .checked_sub(5)
            .ok_or(ParseError::InsufficientLengthSpecified {
                given: len.into(),
                needs: 5,
            })?;
        let client = SslClientFlags(buf.get_u8());
        let verify = SslVerifyStatus(buf.get_u32());
        let mut extensions = Vec::new();
        while ext_len > 0 {
            let rem0 = buf.remaining();
            extensions.push(SslExtensionTlv::parse(buf)?);
            let rem = buf.remaining();
            // The assert enforces that Buf is implemented sanely
            // and not rewound.
            let parsed = rem0.checked_sub(rem).expect("Buf error");
            // We don't enforce u16-sized buffers.
            // Since we don't pass a bound on how much to parse,
            // we can't enforce that the extension parser won't read
            // (slightly) more than 64k.
            // The assert is safe since ext_len was already u16 and the
            // new value is lower.
            ext_len = usize::from(ext_len)
                .checked_sub(parsed)
                .ok_or(ParseError::InsufficientLengthSpecified {
                    given: ext_len.into(),
                    needs: parsed,
                })?
                .try_into()
                .expect("Math error");
        }
        Ok(Self {
            client,
            verify,
            extensions,
        })
    }

    fn encoded_len(&self) -> Result<u16, EncodeError> {
        // 1 for flags, 4 for verify status, plus all nested TLVs
        self.extensions
            .iter()
            .try_fold(5u16, |sum, subtlv| {
                sum.checked_add(subtlv.encoded_len().ok()?)
            })
            .ok_or(EncodeError::ValueTooLarge)
    }

    fn encode(&self, buf: &mut BytesMut) -> Result<(), EncodeError> {
        buf.put_u8(self.client.0);
        buf.put_u32(self.verify.0);
        for ext in self.extensions.iter() {
            ext.encode(buf)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "always_exhaustive"), non_exhaustive)] // Extensions may be added
pub enum ExtensionTlv {
    Alpn(Vec<u8>),
    Authority(String),
    Crc32c(u32),
    UniqueId(Vec<u8>),
    Ssl(Ssl),
    NetNs(String),
}

pub(crate) const PP2_TYPE_ALPN: u8 = 0x01;
pub(crate) const PP2_TYPE_AUTHORITY: u8 = 0x02;
pub(crate) const PP2_TYPE_CRC32C: u8 = 0x03;
pub(crate) const PP2_TYPE_NOOP: u8 = 0x04;
pub(crate) const PP2_TYPE_UNIQUE_ID: u8 = 0x05;
pub(crate) const PP2_TYPE_SSL: u8 = 0x20;
pub(crate) const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21;
pub(crate) const PP2_SUBTYPE_SSL_CN: u8 = 0x22;
pub(crate) const PP2_SUBTYPE_SSL_CIPHER: u8 = 0x23;
pub(crate) const PP2_SUBTYPE_SSL_SIG_ALG: u8 = 0x24;
pub(crate) const PP2_SUBTYPE_SSL_KEY_ALG: u8 = 0x25;
pub(crate) const PP2_TYPE_NETNS: u8 = 0x30;

fn vec_from_buf(buf: &mut impl Buf, len: u16) -> Vec<u8> {
    let mut r = vec![0; len.into()];
    buf.copy_to_slice(&mut r);
    r
}

fn str_from_buf(buf: &mut impl Buf, len: u16) -> Result<String, ParseError> {
    let v = vec_from_buf(buf, len);
    let r = String::from_utf8(v).map_err(|e| ParseError::InvalidUtf8 {
        bytes: e.into_bytes(),
    })?;
    Ok(r)
}

fn ascii_from_buf(buf: &mut impl Buf, len: u16) -> Result<String, ParseError> {
    let s = str_from_buf(buf, len)?;
    if !s.is_ascii() {
        Err(ParseError::InvalidAscii {
            bytes: s.into_bytes(),
        })
    } else {
        Ok(s)
    }
}

impl Tlv for ExtensionTlv {
    fn type_id(&self) -> u8 {
        match self {
            Self::Alpn(_) => PP2_TYPE_ALPN,
            Self::Authority(_) => PP2_TYPE_AUTHORITY,
            Self::Crc32c(_) => PP2_TYPE_CRC32C,
            Self::UniqueId(_) => PP2_TYPE_UNIQUE_ID,
            Self::Ssl(_) => PP2_TYPE_SSL,
            Self::NetNs(_) => PP2_TYPE_NETNS,
        }
    }

    fn value_len(&self) -> Result<u16, EncodeError> {
        match self {
            Self::Alpn(alpn) => alpn.len(),
            Self::Authority(authority) => authority.len(),
            Self::Crc32c(_) => 4,
            Self::UniqueId(id) => id.len(),
            Self::Ssl(data) => data.encoded_len()?.into(),
            Self::NetNs(netns) => netns.len(),
        }
        .try_into()
        .map_err(|_| EncodeError::ValueTooLarge)
    }

    fn encode_value(&self, buf: &mut BytesMut) -> Result<(), EncodeError> {
        match self {
            Self::Alpn(by) | Self::UniqueId(by) => buf.put_slice(by),
            Self::Authority(st) | Self::NetNs(st) => buf.put_slice(st.as_bytes()),
            Self::Crc32c(crc) => buf.put_u32(*crc),
            Self::Ssl(ssl) => ssl.encode(buf)?,
        };
        Ok(())
    }

    fn parse_parts(type_id: u8, len: u16, buf: &mut impl Buf) -> Result<Self, ParseError> {
        Ok(match type_id {
            PP2_TYPE_ALPN => Self::Alpn(vec_from_buf(buf, len)),
            PP2_TYPE_AUTHORITY => Self::Authority(str_from_buf(buf, len)?),
            PP2_TYPE_CRC32C => Self::Crc32c(buf.get_u32()),
            PP2_TYPE_UNIQUE_ID => Self::UniqueId(vec_from_buf(buf, len)),
            PP2_TYPE_SSL => Self::Ssl(Ssl::parse(buf, len)?),
            PP2_TYPE_NETNS => Self::NetNs(ascii_from_buf(buf, len)?),
            _ => return Err(ParseError::InvalidTlvTypeId { type_id }),
        })
    }
}

// Note: this is internal, assumes the first 12 bytes were parsed,
// and ignores the version half of the first byte.
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
    let st = buf.get_u8();

    // No ensure for command byte. We know it must exist.
    let command = st << 4 >> 4;
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
    ensure!(buf.remaining() >= length, UnexpectedEof);

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

    // The full length of address data,
    // including two addresses and two ports
    let address_len = match address_family {
        ProxyAddressFamily::Inet => (4 + 2) * 2,
        ProxyAddressFamily::Inet6 => (16 + 2) * 2,
        ProxyAddressFamily::Unix => 108 * 2,
        ProxyAddressFamily::Unspec => 0,
    };

    let mut ext_len =
        length
            .checked_sub(address_len)
            .ok_or(ParseError::InsufficientLengthSpecified {
                given: length,
                needs: address_len,
            })?;
    ensure!(buf.remaining() >= address_len, UnexpectedEof,);

    let addresses = match address_family {
        ProxyAddressFamily::Unspec => ProxyAddresses::Unspec,
        ProxyAddressFamily::Unix => {
            let mut source = [0u8; 108];
            let mut destination = [0u8; 108];
            buf.copy_to_slice(&mut source[..]);
            buf.copy_to_slice(&mut destination[..]);
            ProxyAddresses::Unix {
                source,
                destination,
            }
        }
        ProxyAddressFamily::Inet => {
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
        }
        ProxyAddressFamily::Inet6 => {
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
        }
    };

    let mut extensions = Vec::new();
    while ext_len > 0 {
        // At this point, we know that remaining() >= ext_len
        if buf.chunk()[0] == PP2_TYPE_NOOP {
            if ext_len < 3 {
                return Err(ParseError::InsufficientLengthSpecified {
                    given: ext_len,
                    needs: 3,
                });
            }
            // Read/skip the type after peeking
            buf.get_u8();
            let skip_len = buf.get_u16();
            let noop_len = 3u16
                .checked_add(skip_len)
                .ok_or(ParseError::LengthOverflow {
                    given: skip_len.into(),
                })?
                .into();
            if noop_len > ext_len {
                return Err(ParseError::InsufficientLengthSpecified {
                    given: ext_len,
                    needs: noop_len,
                });
            }
            ext_len -= noop_len;
        } else {
            let rem0 = buf.remaining();
            extensions.push(ExtensionTlv::parse(buf)?);
            let rem = buf.remaining();
            let parsed = rem0.checked_sub(rem).expect("Buf error");
            ext_len =
                ext_len
                    .checked_sub(parsed)
                    .ok_or(ParseError::InsufficientLengthSpecified {
                        given: ext_len,
                        needs: parsed,
                    })?;
        }
    }

    Ok(super::ProxyHeader::Version2 {
        command,
        transport_protocol,
        addresses,
        extensions,
    })
}

// Currently used in tests, has to be internal for the same reasons
// parse() currently is.
#[cfg(test)]
pub(crate) fn parse_fully(buf: &mut impl Buf) -> Result<super::ProxyHeader, ParseError> {
    let r = parse(buf)?;
    if buf.has_remaining() {
        return Err(ParseError::TrailingData {
            len: buf.remaining(),
        });
    }
    Ok(r)
}

pub(crate) fn encode(
    command: ProxyCommand,
    transport_protocol: ProxyTransportProtocol,
    addresses: ProxyAddresses,
    extensions: &[ExtensionTlv],
) -> Result<BytesMut, EncodeError> {
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
    let address_len: u16 = match addresses {
        ProxyAddresses::Unspec => 0,
        ProxyAddresses::Unix { .. } => 108 + 108,
        ProxyAddresses::Ipv4 { .. } => 4 + 4 + 2 + 2,
        ProxyAddresses::Ipv6 { .. } => 16 + 16 + 2 + 2,
    };
    // With extensions, we need to distinguish len and address_len
    let len = extensions
        .iter()
        .try_fold(address_len, |acc, ext| {
            acc.checked_add(ext.encoded_len().ok()?)
        })
        .ok_or(EncodeError::ValueTooLarge)?;

    let blen = 16usize
        .checked_add(len.into())
        .ok_or(EncodeError::ValueTooLarge)?;
    let mut buf = BytesMut::with_capacity(blen);
    buf.put_slice(&SIG[..]);
    buf.put_slice(&[ver_cmd, fam][..]);
    buf.put_u16(len);

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

    for ext in extensions.iter() {
        ext.encode(&mut buf)?;
    }

    assert_eq!(buf.len(), blen);

    Ok(buf)
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
            parse_fully(&mut &[0u8; 4][..]),
            Ok(ProxyHeader::Version2 {
                command: ProxyCommand::Local,
                addresses: ProxyAddresses::Unspec,
                transport_protocol: ProxyTransportProtocol::Unspec,
                extensions: Vec::new(),
            }),
        );

        let mut prefix = BytesMut::from(&[1u8, 0, 0, 0][..]);
        assert_eq!(
            parse_fully(&mut prefix),
            Ok(ProxyHeader::Version2 {
                command: ProxyCommand::Proxy,
                addresses: ProxyAddresses::Unspec,
                transport_protocol: ProxyTransportProtocol::Unspec,
                extensions: Vec::new(),
            }),
        );
    }

    #[test]
    fn test_ipv4() {
        assert_eq!(
            parse_fully(
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
                    PP2_TYPE_NOOP,
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
                extensions: Vec::new(),
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
                extensions: Vec::new(),
            })
        );
        assert!(data.remaining() == 4); // Consume the entire header
    }

    #[test]
    fn test_ipv6() {
        assert_eq!(
            parse_fully(
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
                    PP2_TYPE_NOOP,
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
                extensions: Vec::new(),
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
                extensions: Vec::new(),
            })
        );
        assert!(data.remaining() == 4); // Consume the entire header
    }

    #[test]
    fn test_invalid_data() {
        let mut data = [0u8; 200];
        rand::thread_rng().fill_bytes(&mut data);
        data[0] = 99; // Make 100% sure it's invalid.
        assert!(parse_fully(&mut &data[..]).is_err());

        assert_eq!(parse_fully(&mut &[0][..]), Err(ParseError::UnexpectedEof));

        assert_eq!(
            parse_fully(
                &mut &[
                    // Proxy command
                    1u8,
                    // Inet << 4 | Stream
                    (1 << 4) | 1,
                    // Length beyond this: 12
                    // 3 bytes is clearly too few if we expect 2 IPv4s and ports
                    0,
                    3,
                    0,
                    0,
                    0,
                ][..]
            ),
            Err(ParseError::InsufficientLengthSpecified {
                given: 3,
                needs: 4 * 2 + 2 * 2,
            }),
        );
    }

    #[test]
    fn test_tlv() {
        use super::ExtensionTlv::*;
        use super::SslExtensionTlv::*;

        assert_eq!(
            parse_fully(
                &mut &[
                    // Proxy command
                    1u8,
                    // Connection type: Unknown
                    0,
                    // TLV length: 3 + 2 + 3 + 11 + 3 + 15
                    0,
                    37,
                    PP2_TYPE_ALPN,
                    0,
                    2,
                    // h2
                    0x68,
                    0x32,
                    PP2_TYPE_AUTHORITY,
                    0,
                    11,
                    // example.org
                    0x65,
                    0x78,
                    0x61,
                    0x6d,
                    0x70,
                    0x6c,
                    0x65,
                    0x2e,
                    0x6f,
                    0x72,
                    0x67,
                    PP2_TYPE_SSL,
                    0,
                    15,
                    0x07,
                    0,
                    0,
                    0,
                    0,
                    PP2_SUBTYPE_SSL_VERSION,
                    0,
                    7,
                    // TLSv1.3.  This is from OpenSSL, to match haproxy.
                    0x54,
                    0x4c,
                    0x53,
                    0x76,
                    0x31,
                    0x2e,
                    0x33,
                ][..]
            ),
            Ok(ProxyHeader::Version2 {
                command: ProxyCommand::Proxy,
                addresses: ProxyAddresses::Unspec,
                transport_protocol: ProxyTransportProtocol::Unspec,
                extensions: vec![
                    Alpn(b"h2".to_vec()),
                    Authority("example.org".to_string()),
                    Ssl(super::Ssl {
                        client: SslClientFlags(7),
                        verify: SslVerifyStatus(0),
                        extensions: vec![Version("TLSv1.3".to_string()),],
                    }),
                ],
            }),
        );
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use bytes::BytesMut;
    use pretty_assertions::assert_eq;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];

    fn signed(buf: &[u8]) -> BytesMut {
        let mut bytes = BytesMut::from(&SIG[..]);
        bytes.extend_from_slice(buf);
        bytes
    }

    #[test]
    fn test_unspec() {
        assert_eq!(
            encode(
                ProxyCommand::Local,
                ProxyTransportProtocol::Unspec,
                ProxyAddresses::Unspec,
                &[],
            ),
            Ok(signed(&[2 << 4, 0, 0, 0][..])),
        );

        assert_eq!(
            encode(
                ProxyCommand::Proxy,
                ProxyTransportProtocol::Unspec,
                ProxyAddresses::Unspec,
                &[],
            ),
            Ok(signed(&[(2 << 4) | 1, 0, 0, 0][..])),
        );
        assert_eq!(
            encode(
                ProxyCommand::Proxy,
                ProxyTransportProtocol::Unspec,
                ProxyAddresses::Ipv4 {
                    source: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 65535),
                    destination: SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 9012),
                },
                &[],
            ),
            Ok(signed(
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
            )),
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
                &[],
            ),
            Ok(signed(
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
            )),
        );
        assert_eq!(
            encode(
                ProxyCommand::Local,
                ProxyTransportProtocol::Datagram,
                ProxyAddresses::Ipv4 {
                    source: SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), 324),
                    destination: SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 2187),
                },
                &[],
            ),
            Ok(signed(
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
            )),
        );
    }

    #[test]
    fn test_ipv6() {
        assert_eq!(
            encode(
                ProxyCommand::Local,
                ProxyTransportProtocol::Datagram,
                ProxyAddresses::Ipv6 {
                    source: SocketAddrV6::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 8192, 0, 0,),
                    destination: SocketAddrV6::new(
                        Ipv6Addr::new(65535, 65535, 32767, 32766, 111, 222, 333, 444),
                        0,
                        0,
                        0,
                    ),
                },
                &[],
            ),
            Ok(signed(
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
            )),
        );
    }

    #[test]
    fn test_tlv() {
        use super::ExtensionTlv::*;
        use super::SslExtensionTlv::*;

        assert_eq!(
            encode(
                ProxyCommand::Proxy,
                ProxyTransportProtocol::Unspec,
                ProxyAddresses::Unspec,
                &[
                    Alpn(b"h2".to_vec()),
                    Authority("example.org".to_string()),
                    Ssl(super::Ssl {
                        client: SslClientFlags(7),
                        verify: SslVerifyStatus(0),
                        extensions: vec![Version("TLSv1.3".to_string()),],
                    }),
                ],
            ),
            Ok(signed(
                &[
                    // Version 2,
                    // Proxy command
                    0x21u8,
                    // Connection type: Unknown
                    0,
                    // TLV length: 3 + 2 + 3 + 11 + 3 + 15
                    0,
                    37,
                    PP2_TYPE_ALPN,
                    0,
                    2,
                    // h2
                    0x68,
                    0x32,
                    PP2_TYPE_AUTHORITY,
                    0,
                    11,
                    // example.org
                    0x65,
                    0x78,
                    0x61,
                    0x6d,
                    0x70,
                    0x6c,
                    0x65,
                    0x2e,
                    0x6f,
                    0x72,
                    0x67,
                    PP2_TYPE_SSL,
                    0,
                    15,
                    0x07,
                    0,
                    0,
                    0,
                    0,
                    PP2_SUBTYPE_SSL_VERSION,
                    0,
                    7,
                    // TLSv1.3.  This is from OpenSSL, to match haproxy.
                    0x54,
                    0x4c,
                    0x53,
                    0x76,
                    0x31,
                    0x2e,
                    0x33,
                ][..]
            )),
        );
    }
}
