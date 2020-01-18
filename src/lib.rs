//! The HAProxy PROXY protocol.
//!
//! The main point of this is to emit PROXY headers, not to receive them, but
//! the library will try to implement both as far as possible, no matter how
//! unergonomic receiving would be.
//!
//! The protocol has been implemented per the specification available here:
//! <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]

pub mod error;
mod protocol;

pub use self::protocol::*;
