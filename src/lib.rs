//! #quick-g3
//! 
//!  A Quic and Http3 implementation in Rust
//! 
//!  This library implements;
//!  - QUIC (RFC 9000)
//!  - HTTP/3 (RFC 9114)


pub mod error;
pub mod quic;
pub mod h3;
pub mod server;

pub use error::{Error, Result};
pub use server::{Server, ServerConfig};

pub use h3::{Request, Response, StatusCode, Method, Header};

