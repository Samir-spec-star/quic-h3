use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::{Error, Result};
use crate::quic::{read_varint, write_varint, varint_len};
/// HTTP/3 frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3FrameType {
    /// DATA frame (0x00) - carries request/response
    Data = 0x00,
    /// HEADERS frame (0x01) - carries compressed headers
    Headers = 0x01,
    /// CANCEL_PUSH frame (0x03)
    CancelPush = 0x03,
    /// SETTINGS frame (0x04) - connection settings
    Settings = 0x04,
    /// PUSH_PROMISE frame (0x05)
    PushPromise = 0x05,
    /// GOAWAY frame (0x07) - graceful shutdown
    GoAway = 0x07,
    /// MAX_PUSH_ID frame (0x0d)
    MaxPushId = 0x0d,
}
impl H3FrameType {
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Headers),
            0x03 => Some(Self::CancelPush),
            0x04 => Some(Self::Settings),
            0x05 => Some(Self::PushPromise),
            0x07 => Some(Self::GoAway),
            0x0d => Some(Self::MaxPushId),
            _ => None,
        }
    }
}
/// A parsed HTTP/3 frame
#[derive(Debug, Clone)]
pub enum H3Frame {
    /// DATA frame with payload
    Data(Bytes),
    
    /// HEADERS frame with encoded headers
    Headers(Bytes),
    
    /// SETTINGS frame
    Settings(SettingsFrame),
    
    /// GOAWAY frame
    GoAway { stream_id: u64 },
    
    /// Unknown/reserved frame (skip it)
    Unknown { frame_type: u64, payload: Bytes },
}
/// HTTP/3 Settings
#[derive(Debug, Clone, Default)]
pub struct SettingsFrame {
    /// Maximum size of a header block
    pub max_field_section_size: Option<u64>,
    /// QPACK maximum table capacity
    pub qpack_max_table_capacity: Option<u64>,
    /// QPACK blocked streams
    pub qpack_blocked_streams: Option<u64>,
}
/// Setting identifiers
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
impl H3Frame {
    /// Parse an HTTP/3 frame from a buffer
    pub fn parse<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooShort {
                needed: 2,
                have: buf.remaining(),
            });
        }
        let frame_type = read_varint(buf)?;
        let length = read_varint(buf)? as usize;
        if buf.remaining() < length {
            return Err(Error::BufferTooShort {
                needed: length,
                have: buf.remaining(),
            });
        }
        let payload = buf.copy_to_bytes(length);
        match H3FrameType::from_u64(frame_type) {
            Some(H3FrameType::Data) => Ok(H3Frame::Data(payload)),
            
            Some(H3FrameType::Headers) => Ok(H3Frame::Headers(payload)),
            
            Some(H3FrameType::Settings) => {
                let settings = SettingsFrame::parse(payload)?;
                Ok(H3Frame::Settings(settings))
            }
            
            Some(H3FrameType::GoAway) => {
                let mut p = payload;
                let stream_id = read_varint(&mut p)?;
                Ok(H3Frame::GoAway { stream_id })
            }
            
            _ => Ok(H3Frame::Unknown {
                frame_type,
                payload,
            }),
        }
    }
    /// Write a DATA frame
    pub fn write_data<B: BufMut>(buf: &mut B, data: &[u8]) {
        write_varint(buf, H3FrameType::Data as u64).unwrap();
        write_varint(buf, data.len() as u64).unwrap();
        buf.put_slice(data);
    }
    /// Write a HEADERS frame
    pub fn write_headers<B: BufMut>(buf: &mut B, encoded_headers: &[u8]) {
        write_varint(buf, H3FrameType::Headers as u64).unwrap();
        write_varint(buf, encoded_headers.len() as u64).unwrap();
        buf.put_slice(encoded_headers);
    }
    /// Write a SETTINGS frame
    pub fn write_settings<B: BufMut>(buf: &mut B, settings: &SettingsFrame) {
        let mut payload = BytesMut::new();
        settings.write(&mut payload);
        
        write_varint(buf, H3FrameType::Settings as u64).unwrap();
        write_varint(buf, payload.len() as u64).unwrap();
        buf.put_slice(&payload);
    }
    /// Write a GOAWAY frame
    pub fn write_goaway<B: BufMut>(buf: &mut B, stream_id: u64) {
        let len = varint_len(stream_id);
        write_varint(buf, H3FrameType::GoAway as u64).unwrap();
        write_varint(buf, len as u64).unwrap();
        write_varint(buf, stream_id).unwrap();
    }
}
impl SettingsFrame {
    pub fn parse(mut payload: Bytes) -> Result<Self> {
        let mut settings = SettingsFrame::default();
        while payload.has_remaining() {
            let id = read_varint(&mut payload)?;
            let value = read_varint(&mut payload)?;
            match id {
                SETTINGS_MAX_FIELD_SECTION_SIZE => {
                    settings.max_field_section_size = Some(value);
                }
                SETTINGS_QPACK_MAX_TABLE_CAPACITY => {
                    settings.qpack_max_table_capacity = Some(value);
                }
                SETTINGS_QPACK_BLOCKED_STREAMS => {
                    settings.qpack_blocked_streams = Some(value);
                }
                _ => {
                    // Unknown setting, ignore (RFC 9114 requirement)
                    tracing::debug!("Unknown HTTP/3 setting: 0x{:x} = {}", id, value);
                }
            }
        }
        Ok(settings)
    }
    pub fn write<B: BufMut>(&self, buf: &mut B) {
        if let Some(v) = self.max_field_section_size {
            write_varint(buf, SETTINGS_MAX_FIELD_SECTION_SIZE).unwrap();
            write_varint(buf, v).unwrap();
        }
        if let Some(v) = self.qpack_max_table_capacity {
            write_varint(buf, SETTINGS_QPACK_MAX_TABLE_CAPACITY).unwrap();
            write_varint(buf, v).unwrap();
        }
        if let Some(v) = self.qpack_blocked_streams {
            write_varint(buf, SETTINGS_QPACK_BLOCKED_STREAMS).unwrap();
            write_varint(buf, v).unwrap();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_data_frame() {
        // DATA frame: type=0x00, length=5, payload="hello"
        let mut buf = Bytes::from_static(&[0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);
        let frame = H3Frame::parse(&mut buf).unwrap();
        
        if let H3Frame::Data(data) = frame {
            assert_eq!(&data[..], b"hello");
        } else {
            panic!("Expected DATA frame");
        }
    }
    #[test]
    fn test_write_data_frame() {
        let mut buf = BytesMut::new();
        H3Frame::write_data(&mut buf, b"hello");
        
        assert_eq!(&buf[..], &[0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);
    }
    #[test]
    fn test_parse_headers_frame() {
        // HEADERS frame: type=0x01, length=3, payload=[1,2,3]
        let mut buf = Bytes::from_static(&[0x01, 0x03, 0x01, 0x02, 0x03]);
        let frame = H3Frame::parse(&mut buf).unwrap();
        
        if let H3Frame::Headers(data) = frame {
            assert_eq!(&data[..], &[0x01, 0x02, 0x03]);
        } else {
            panic!("Expected HEADERS frame");
        }
    }
    #[test]
    fn test_settings_frame() {
        let settings = SettingsFrame {
            max_field_section_size: Some(8192),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
        };
        
        let mut buf = BytesMut::new();
        H3Frame::write_settings(&mut buf, &settings);
        
        // Parse it back
        let mut read_buf = buf.freeze();
        let frame = H3Frame::parse(&mut read_buf).unwrap();
        
        if let H3Frame::Settings(parsed) = frame {
            assert_eq!(parsed.max_field_section_size, Some(8192));
        } else {
            panic!("Expected SETTINGS frame");
        }
    }
}