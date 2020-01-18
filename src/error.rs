use thiserror::Error;

#[derive(Error, Debug)]
pub enum BinaryParsingError {
    #[error("too small buffer, expected minimum {0} bytes")]
    BufferSmall(usize),

    #[error("invalid command given: 0x{0:X}")]
    InvalidCommand(u8),

    #[error("invalid transport protocol given: 0x{0:X}")]
    InvalidTransportProtocol(u8),

    #[error("invalid address family given: 0x{0:X}")]
    InvalidAddressFamily(u8),

    #[error("invalid version: {0}")]
    InvalidVersion(u8),
}

#[derive(Error, Debug)]
pub enum Version1ParsingError {
    #[error("unknown address family given")]
    InvalidAddressFamily,

    #[error("expected a space at {1} where 0x{0:X} was given")]
    ExpectedSpace(u8, usize),

    #[error("expected a CRLF")]
    ExpectedCRLF,

    #[error("the addresses were not of the same family")]
    UnequalAddressFamilies,
}

#[derive(Error, Debug)]
pub enum EncodingError {
    #[error("cannot have a destination port but no source port")]
    DestinationPortButNoSource,
}

#[derive(Error, Debug)]
pub enum DecodingError {
    #[error("the data given is not a PROXY protocol header")]
    NotProxyHeader,

    #[error("too small buffer, expected minimum {0} bytes")]
    BufferSmall(usize),

    #[error("cannot parse address: {0} - {1}")]
    AddrParse(std::net::AddrParseError, String),

    #[error("cannot parse string: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("cannot parse integer: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("error parsing binary header: {0}")]
    BinaryParsing(#[from] BinaryParsingError),

    #[error("error parsing human readable header: {0}")]
    Version1Parsing(#[from] Version1ParsingError),
}
