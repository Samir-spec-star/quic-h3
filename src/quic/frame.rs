use super::varint::{read_varint, write_varint};
use crate::{Error, Result};
use bytes::{Buf, BufMut, Bytes};
/// QUIC Frame types
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// PADDING frame (type 0x00) - used to increase packet size
    Padding,

    /// PING frame (type 0x01) - used to keep connection alive
    Ping,

    /// ACK frame (type 0x02 or 0x03)
    Ack(AckFrame),

    /// CRYPTO frame (type 0x06) - carries TLS handshake data
    Crypto(CryptoFrame),

    /// STREAM frame (types 0x08-0x0f)
    Stream(StreamFrame),

    /// CONNECTION_CLOSE frame (type 0x1c or 0x1d)
    ConnectionClose(ConnectionCloseFrame),
}
/// ACK frame structure
#[derive(Debug, Clone, PartialEq)]
pub struct AckFrame {
    /// Largest packet number being acknowledged
    pub largest_ack: u64,
    /// Delay since receiving the largest acknowledged packet (in microseconds)
    pub ack_delay: u64,
    /// Number of ACK ranges following the first
    pub ack_range_count: u64,
    /// Number of packets being acknowledged in the first range
    pub first_ack_range: u64,
    // Note: Additional ACK ranges not implemented for simplicity
}
/// CRYPTO frame structure
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoFrame {
    /// Byte offset in the crypto stream
    pub offset: u64,
    /// The crypto data (TLS handshake messages)
    pub data: Bytes,
}
/// STREAM frame structure
#[derive(Debug, Clone, PartialEq)]
pub struct StreamFrame {
    /// Stream ID
    pub stream_id: u64,
    /// Offset in the stream (if present)
    pub offset: u64,
    /// Whether this is the final data on the stream
    pub fin: bool,
    /// The stream data
    pub data: Bytes,
}
/// CONNECTION_CLOSE frame structure
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionCloseFrame {
    /// Error code
    pub error_code: u64,
    /// Frame type that triggered the error (if applicable)
    pub frame_type: Option<u64>,
    /// Human-readable reason phrase
    pub reason_phrase: String,
}
impl Frame {
    /// Parse a frame from a buffer
    pub fn parse<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(Error::BufferTooShort { needed: 1, have: 0 });
        }
        let frame_type = read_varint(buf)?;
        match frame_type {
            0x00 => Ok(Frame::Padding),
            0x01 => Ok(Frame::Ping),
            0x02 | 0x03 => {
                let largest_ack = read_varint(buf)?;
                let ack_delay = read_varint(buf)?;
                let ack_range_count = read_varint(buf)?;
                let first_ack_range = read_varint(buf)?;

                // Skip additional ACK ranges for now
                for _ in 0..ack_range_count {
                    read_varint(buf)?; // gap
                    read_varint(buf)?; // ack range length
                }
                Ok(Frame::Ack(AckFrame {
                    largest_ack,
                    ack_delay,
                    ack_range_count,
                    first_ack_range,
                }))
            }
            0x06 => {
                let offset = read_varint(buf)?;
                let length = read_varint(buf)? as usize;

                if buf.remaining() < length {
                    return Err(Error::BufferTooShort {
                        needed: length,
                        have: buf.remaining(),
                    });
                }

                let data = buf.copy_to_bytes(length);

                Ok(Frame::Crypto(CryptoFrame { offset, data }))
            }
            0x08..=0x0f => {
                let stream_type = frame_type as u8;
                let stream_id = read_varint(buf)?;

                let offset = if stream_type & 0x04 != 0 {
                    read_varint(buf)?
                } else {
                    0
                };

                let length = if stream_type & 0x02 != 0 {
                    read_varint(buf)? as usize
                } else {
                    buf.remaining()
                };

                let fin = stream_type & 0x01 != 0;

                if buf.remaining() < length {
                    return Err(Error::BufferTooShort {
                        needed: length,
                        have: buf.remaining(),
                    });
                }

                let data = buf.copy_to_bytes(length);

                Ok(Frame::Stream(StreamFrame {
                    stream_id,
                    offset,
                    fin,
                    data,
                }))
            }
            0x1c | 0x1d => {
                let is_app_error = frame_type == 0x1d;
                let error_code = read_varint(buf)?;

                let frame_type_field = if !is_app_error {
                    Some(read_varint(buf)?)
                } else {
                    None
                };

                let reason_len = read_varint(buf)? as usize;
                if buf.remaining() < reason_len {
                    return Err(Error::BufferTooShort {
                        needed: reason_len,
                        have: buf.remaining(),
                    });
                }

                let reason_bytes = buf.copy_to_bytes(reason_len);
                let reason_phrase = String::from_utf8_lossy(&reason_bytes).to_string();

                Ok(Frame::ConnectionClose(ConnectionCloseFrame {
                    error_code,
                    frame_type: frame_type_field,
                    reason_phrase,
                }))
            }
            _ => Err(Error::InvalidVarint(format!(
                "Unknown frame type: 0x{:02x}",
                frame_type
            ))),
        }
    }
    /// Write a PADDING frame
    pub fn write_padding<B: BufMut>(buf: &mut B) {
        buf.put_u8(0x00);
    }
    /// Write a PING frame
    pub fn write_ping<B: BufMut>(buf: &mut B) {
        buf.put_u8(0x01);
    }
    /// Write an ACK frame
    pub fn write_ack<B: BufMut>(buf: &mut B, ack: &AckFrame) -> Result<()> {
        write_varint(buf, 0x02)?; // ACK without ECN
        write_varint(buf, ack.largest_ack)?;
        write_varint(buf, ack.ack_delay)?;
        write_varint(buf, ack.ack_range_count)?;
        write_varint(buf, ack.first_ack_range)?;
        Ok(())
    }
    pub fn write_stream<B: bytes::BufMut>(buf: &mut B, stream_id: u64, data: &[u8], fin: bool) -> crate::Result<()> {
        let mut type_byte = 0x0a; // 0x08 | 0x02 (Length present)
        if fin { type_byte |= 0x01; }
        write_varint(buf, type_byte as u64)?;
        write_varint(buf, stream_id)?;
        write_varint(buf, data.len() as u64)?;
        buf.put_slice(data);
        Ok(())
    }
}

pub fn generate_ack(received_packets: &[u64]) -> Option<AckFrame> {
    if received_packets.is_empty() {
        return None;
    }
    let mut packets: Vec<u64> = received_packets.to_vec();
    packets.sort_unstable();
    packets.dedup();
    packets.reverse(); // Largest first
    let largest_ack = packets[0];
    
    // For simplicity, we'll just acknowledge the first contiguous range
    // A full implementation would encode multiple ranges
    let mut first_range = 0u64;
    for i in 1..packets.len() {
        if packets[i - 1] - packets[i] == 1 {
            first_range += 1;
        } else {
            break;
        }
    }
    Some(AckFrame {
        largest_ack,
        ack_delay: 0,
        ack_range_count: 0,
        first_ack_range: first_range,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_padding() {
        let mut buf = Bytes::from_static(&[0x00]);
        let frame = Frame::parse(&mut buf).unwrap();
        assert_eq!(frame, Frame::Padding);
    }
    #[test]
    fn test_parse_ping() {
        let mut buf = Bytes::from_static(&[0x01]);
        let frame = Frame::parse(&mut buf).unwrap();
        assert_eq!(frame, Frame::Ping);
    }
    #[test]
    fn test_write_ping() {
        let mut buf = bytes::BytesMut::new();
        Frame::write_ping(&mut buf);
        assert_eq!(&buf[..], &[0x01]);
    }
    #[test]
fn test_generate_ack() {
    let received = vec![0, 1, 2, 5, 6, 7];
    let ack = generate_ack(&received).unwrap();
    
    assert_eq!(ack.largest_ack, 7);
    assert_eq!(ack.first_ack_range, 2); // 7, 6, 5 are contiguous
}
    #[test]
    fn test_parse_ack() {
        // ACK frame: type=0x02, largest=10, delay=5, range_count=0, first_range=5
        let mut buf = Bytes::from_static(&[0x02, 0x0a, 0x05, 0x00, 0x05]);
        let frame = Frame::parse(&mut buf).unwrap();

        if let Frame::Ack(ack) = frame {
            assert_eq!(ack.largest_ack, 10);
            assert_eq!(ack.ack_delay, 5);
            assert_eq!(ack.ack_range_count, 0);
            assert_eq!(ack.first_ack_range, 5);
        } else {
            panic!("Expected ACK frame");
        }
    }
}
