use bytes::Buf;
use crate::{Error, Result};
/// Connection ID - identifies a QUIC connection
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    /// The raw bytes of the connection ID (max 20 bytes)
    bytes: Vec<u8>,
}
impl ConnectionId {
    /// Create a new connection ID from bytes
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > 20 {
            return Err(Error::InvalidVarint(
                "Connection ID cannot exceed 20 bytes".to_string()
            ));
        }
        Ok(Self { bytes })
    }
    /// Create an empty connection ID
    pub fn empty() -> Self {
        Self { bytes: Vec::new() }
    }
    /// Get the length of the connection ID
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    /// Check if connection ID is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
/// QUIC packet types for Long Header packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    /// Initial packet (type 0x00)
    Initial,
    /// 0-RTT packet (type 0x01)
    ZeroRtt,
    /// Handshake packet (type 0x02)
    Handshake,
    /// Retry packet (type 0x03)
    Retry,
}
impl LongPacketType {
    /// Convert from the 2-bit type field
    pub fn from_bits(bits: u8) -> Result<Self> {
        match bits & 0x03 {
            0x00 => Ok(Self::Initial),
            0x01 => Ok(Self::ZeroRtt),
            0x02 => Ok(Self::Handshake),
            0x03 => Ok(Self::Retry),
            _ => unreachable!(),
        }
    }
    /// Convert to the 2-bit type field
    pub fn to_bits(self) -> u8 {
        match self {
            Self::Initial => 0x00,
            Self::ZeroRtt => 0x01,
            Self::Handshake => 0x02,
            Self::Retry => 0x03,
        }
    }
}
/// Long Header packet structure
#[derive(Debug, Clone)]
pub struct LongHeader {
    /// Packet type
    pub packet_type: LongPacketType,
    /// QUIC version
    pub version: u32,
    /// Destination Connection ID
    pub dcid: ConnectionId,
    /// Source Connection ID  
    pub scid: ConnectionId,
}
impl LongHeader {
    /// Parse a long header from a buffer
    pub fn parse<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 7 {
            return Err(Error::BufferTooShort {
                needed: 7,
                have: buf.remaining(),
            });
        }
        let first_byte = buf.get_u8();
        
        // Verify this is a long header (bit 7 = 1)
        if first_byte & 0x80 == 0 {
            return Err(Error::InvalidVarint(
                "Expected long header, got short header".to_string()
            ));
        }
        // Extract packet type (bits 4-5)
        let packet_type = LongPacketType::from_bits((first_byte & 0x30) >> 4)?;
        
        // Read version
        let version = buf.get_u32();
        // Read DCID
        let dcid_len = buf.get_u8() as usize;
        if buf.remaining() < dcid_len {
            return Err(Error::BufferTooShort {
                needed: dcid_len,
                have: buf.remaining(),
            });
        }
        let dcid = ConnectionId::new(buf.copy_to_bytes(dcid_len).to_vec())?;
        // Read SCID
        let scid_len = buf.get_u8() as usize;
        if buf.remaining() < scid_len {
            return Err(Error::BufferTooShort {
                needed: scid_len,
                have: buf.remaining(),
            });
        }
        let scid = ConnectionId::new(buf.copy_to_bytes(scid_len).to_vec())?;
        Ok(Self {
            packet_type,
            version,
            dcid,
            scid,
        })
    }
}
/// Short Header packet structure (used after handshake)
#[derive(Debug, Clone)]
pub struct ShortHeader {
    /// Destination Connection ID
    pub dcid: ConnectionId,
    /// Packet number (decoded)
    pub packet_number: u64,
}
/// QUIC Version constants
pub mod version {
    /// QUIC version 1 (RFC 9000)
    pub const QUIC_V1: u32 = 0x00000001;
    /// QUIC version 2 (RFC 9369)
    pub const QUIC_V2: u32 = 0x6b3343cf;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_connection_id() {
        let cid = ConnectionId::new(vec![1, 2, 3, 4]).unwrap();
        assert_eq!(cid.len(), 4);
        assert_eq!(cid.as_bytes(), &[1, 2, 3, 4]);
    }
    #[test]
    fn test_connection_id_max_length() {
        let cid = ConnectionId::new(vec![0; 20]).unwrap();
        assert_eq!(cid.len(), 20);
        
        // Should fail for > 20 bytes
        assert!(ConnectionId::new(vec![0; 21]).is_err());
    }
    #[test]
    fn test_long_packet_type() {
        assert_eq!(LongPacketType::from_bits(0x00).unwrap(), LongPacketType::Initial);
        assert_eq!(LongPacketType::from_bits(0x01).unwrap(), LongPacketType::ZeroRtt);
        assert_eq!(LongPacketType::from_bits(0x02).unwrap(), LongPacketType::Handshake);
        assert_eq!(LongPacketType::from_bits(0x03).unwrap(), LongPacketType::Retry);
    }
}