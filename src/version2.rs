use bytes::Buf;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {}

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
    Dgram,
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

enum ProxyAddressFamily {
    Unspec,
    Inet,
    Inet6,
    Unix,
}

pub(crate) fn parse(buf: &mut impl Buf) -> Result<super::ProxyHeader> {
    unimplemented!()
}
