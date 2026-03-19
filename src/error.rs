use thiserror::Error;
/// Main error type for the library
#[derive(Debug, Error)]
pub enum Error {
    // ===== QUIC Transport Errors =====
    
    #[error("Invalid varint: {0}")]
    InvalidVarint(String),
    #[error("Buffer too short: need {needed} bytes, have {have}")]
    BufferTooShort { needed: usize, have: usize },
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),
    #[error("Invalid frame: {0}")]
    InvalidFrame(String),
    #[error("Invalid connection ID: {0}")]
    InvalidConnectionId(String),
    // ===== Crypto Errors =====
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    // ===== Stream Errors =====
    
    #[error("Stream error: {0}")]
    Stream(String),
    #[error("Stream {0} not found")]
    StreamNotFound(u64),
    #[error("Stream {0} is closed")]
    StreamClosed(u64),
    #[error("Flow control blocked: {0}")]
    FlowControlBlocked(String),
    // ===== HTTP/3 Errors =====
    
    #[error("HTTP/3 error: {0}")]
    H3(String),
    #[error("Invalid HTTP/3 frame type: 0x{0:x}")]
    InvalidH3FrameType(u64),
    #[error("QPACK error: {0}")]
    Qpack(String),
    #[error("Invalid header: {0}")]
    InvalidHeader(String),
    // ===== Connection Errors =====
    
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Connection closed: {reason} (code: {code})")]
    ConnectionClosed { code: u64, reason: String },
    #[error("Connection timeout")]
    Timeout,
    #[error("Max connections reached")]
    MaxConnectionsReached,
    // ===== I/O Errors =====
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
/// HTTP/3 specific error codes (RFC 9114)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3ErrorCode {
    /// No error
    NoError = 0x100,
    /// General protocol error
    GeneralProtocolError = 0x101,
    /// Internal error
    InternalError = 0x102,
    /// Stream creation error
    StreamCreationError = 0x103,
    /// Closed critical stream
    ClosedCriticalStream = 0x104,
    /// Frame unexpected
    FrameUnexpected = 0x105,
    /// Frame error
    FrameError = 0x106,
    /// Excessive load
    ExcessiveLoad = 0x107,
    /// ID error
    IdError = 0x108,
    /// Settings error
    SettingsError = 0x109,
    /// Missing settings
    MissingSettings = 0x10a,
    /// Request rejected
    RequestRejected = 0x10b,
    /// Request cancelled
    RequestCancelled = 0x10c,
    /// Request incomplete
    RequestIncomplete = 0x10d,
    /// Message error
    MessageError = 0x10e,
    /// Connect error
    ConnectError = 0x10f,
    /// Version fallback
    VersionFallback = 0x110,
}
impl H3ErrorCode {
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}
pub type Result<T> = std::result::Result<T, Error>;
/// Extension trait for adding context to errors
pub trait ResultExt<T> {
    fn context(self, msg: &str) -> Result<T>;
}
impl<T, E: std::error::Error> ResultExt<T> for std::result::Result<T, E> {
    fn context(self, msg: &str) -> Result<T> {
        self.map_err(|e| Error::Connection(format!("{}: {}", msg, e)))
    }
}