//! QUIC Transport Protocol implementation
//! 
//! This module implements the core QUIC protocol components:
//!  - variable-length integer encoding (varint)
//!  - Packet parsing and serialization 
//!  - Frame handling 
//!  - Connection management 
//!  - Stream multiplexing 


pub mod varint;
pub mod packet;
pub mod frame;
pub mod crypto;
pub mod connection;
pub mod stream;
pub mod streams;
pub mod recovery;
// Re-export 
pub use varint::{read_varint, write_varint, varint_len, MAX_VARINT};
pub use packet::{ConnectionId, LongHeader, LongPacketType, ShortHeader};
pub use frame::{Frame, AckFrame, CryptoFrame, StreamFrame, ConnectionCloseFrame};
pub use crypto::{derive_initial_secrets, generate_connection_id, ConnectionSecrets, PacketKey};
pub use connection::{Connection, ConnectionState, Role};
pub use stream::{Stream, StreamType, SendState, RecvState, FlowControl};
pub use streams::StreamManager;
pub use recovery::{RecoveryManager, RecoveryStats, SentPacket, RttEstimator, CongestionController};

