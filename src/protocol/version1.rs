/// The 6 bytes required to notify of being a V1 binary PROXY protocol
/// connection.
///
/// Excerpt from the specification:
///
/// > This is the format specified in version 1 of the protocol. It consists in one
/// > line of US-ASCII text matching exactly the following block, sent immediately
/// > and at once upon the connection establishment and prepended before any data
/// > flowing from the sender to the receiver :
/// >
/// >   - a string identifying the protocol : "PROXY" ( \x50 \x52 \x4F \x58 \x59 )
/// >     Seeing this string indicates that this is version 1 of the protocol.
/// >
/// >   - exactly one space : " " ( \x20 )
pub const CONNECTION_PREFIX: [u8; 6] = [b'P', b'R', b'O', b'X', b'Y', b' '];

/// The CR-LF sequence (commonly denoted `\r\n`).
pub const CRLF: [u8; 2] = [0x0D, 0x0A];

/// The CR-LF sequence (commonly denoted `\r\n`).
pub const CRLF_STR: &str = "\x0D\x0A";

/// The IPv4 family denotation.
pub const TCP4: [u8; 4] = [b'T', b'C', b'P', b'4'];

/// The IPv4 family denotation.
pub const TCP4_STR: &str = "TCP4";

/// The IPv6 family denotation.
pub const TCP6: [u8; 4] = [b'T', b'C', b'P', b'6'];

/// The IPv6 family denotation.
pub const TCP6_STR: &str = "TCP6";

/// The UNKNOWN family denotation.
pub const UNKNOWN: [u8; 7] = [b'U', b'N', b'K', b'N', b'O', b'W', b'N'];

/// The UNKNOWN family denotation.
pub const UNKNOWN_STR: &str = "UNKNOWN";

/// The smallest possible header.
pub const UNKNOWN_PROXY_HEADER: [u8; 15] = [
    b'P', b'R', b'O', b'X', b'Y', b' ', b'U', b'N', b'K', b'N', b'O', b'W', b'N', 0x0D, 0x0A,
];

#[allow(dead_code)] // Compiler bug - https://github.com/rust-lang/rust/issues/64362
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ProxyAddressFamily {
    Unknown,
    IPv4,
    IPv6,
}

impl ProxyAddressFamily {
    pub fn min_length(self) -> usize {
        match self {
            ProxyAddressFamily::Unknown => 0,
            ProxyAddressFamily::IPv4 => 7,
            ProxyAddressFamily::IPv6 => 3,
        }
    }
}
