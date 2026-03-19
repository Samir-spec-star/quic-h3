use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::{Error, Result};
/// Static table entries (RFC 9204, Appendix A)
/// Format: (index, name, value)
const STATIC_TABLE: &[(u8, &str, &str)] = &[
    (0, ":authority", ""),
    (1, ":path", "/"),
    (2, "age", "0"),
    (3, "content-disposition", ""),
    (4, "content-length", "0"),
    (5, "cookie", ""),
    (6, "date", ""),
    (7, "etag", ""),
    (8, "if-modified-since", ""),
    (9, "if-none-match", ""),
    (10, "last-modified", ""),
    (11, "link", ""),
    (12, "location", ""),
    (13, "referer", ""),
    (14, "set-cookie", ""),
    (15, ":method", "CONNECT"),
    (16, ":method", "DELETE"),
    (17, ":method", "GET"),
    (18, ":method", "HEAD"),
    (19, ":method", "OPTIONS"),
    (20, ":method", "POST"),
    (21, ":method", "PUT"),
    (22, ":scheme", "http"),
    (23, ":scheme", "https"),
    (24, ":status", "103"),
    (25, ":status", "200"),
    (26, ":status", "304"),
    (27, ":status", "404"),
    (28, ":status", "500"),
    (29, "accept", "*/*"),
    (30, "accept", "application/dns-message"),
    (31, "accept-encoding", "gzip, deflate, br"),
    (32, "accept-ranges", "bytes"),
    (33, "access-control-allow-headers", "cache-control"),
    (34, "access-control-allow-headers", "content-type"),
    (35, "access-control-allow-origin", "*"),
    (36, "cache-control", "max-age=0"),
    (37, "cache-control", "max-age=2592000"),
    (38, "cache-control", "max-age=604800"),
    (39, "cache-control", "no-cache"),
    (40, "cache-control", "no-store"),
    (41, "cache-control", "public, max-age=31536000"),
    (42, "content-encoding", "br"),
    (43, "content-encoding", "gzip"),
    (44, "content-type", "application/dns-message"),
    (45, "content-type", "application/javascript"),
    (46, "content-type", "application/json"),
    (47, "content-type", "application/x-www-form-urlencoded"),
    (48, "content-type", "image/gif"),
    (49, "content-type", "image/jpeg"),
    (50, "content-type", "image/png"),
    (51, "content-type", "text/css"),
    (52, "content-type", "text/html; charset=utf-8"),
    (53, "content-type", "text/plain"),
    (54, "content-type", "text/plain;charset=utf-8"),
    (55, "range", "bytes=0-"),
    (56, "strict-transport-security", "max-age=31536000"),
    (57, "strict-transport-security", "max-age=31536000; includesubdomains"),
    (58, "strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    (59, "vary", "accept-encoding"),
    (60, "vary", "origin"),
    (61, "x-content-type-options", "nosniff"),
    (62, "x-xss-protection", "1; mode=block"),
    (63, ":status", "100"),
    (64, ":status", "204"),
    (65, ":status", "206"),
    (66, ":status", "302"),
    (67, ":status", "400"),
    (68, ":status", "403"),
    (69, ":status", "421"),
    (70, ":status", "425"),
    (71, ":status", "500"),
];
/// An HTTP header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}
impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}
/// QPACK Encoder (simplified, no dynamic table)
pub struct QpackEncoder;
impl QpackEncoder {
    /// Encode a list of headers
    pub fn encode(headers: &[Header]) -> Bytes {
        let mut buf = BytesMut::new();
        
        // Required Insert Count = 0 (no dynamic table)
        buf.put_u8(0x00);
        // Delta Base = 0
        buf.put_u8(0x00);
        for header in headers {
            Self::encode_header(&mut buf, header);
        }
        buf.freeze()
    }
    fn encode_header<B: BufMut>(buf: &mut B, header: &Header) {
        // Try to find in static table (exact match)
        if let Some((idx, _, _)) = STATIC_TABLE.iter()
            .find(|(_, n, v)| *n == header.name && *v == header.value)
        {
            // Indexed Field Line (Static Table)
            // 1 1 x x x x x x (prefix 6)
            Self::encode_integer(buf, 0xc0, 6, *idx as u64);
            return;
        }
        // Try to find name-only match in static table
        if let Some((idx, _, _)) = STATIC_TABLE.iter()
            .find(|(_, n, _)| *n == header.name)
        {
            // Literal Field Line With Name Reference (Static Table)
            // 0 1 0 1 x x x x (prefix 4)
            Self::encode_integer(buf, 0x50, 4, *idx as u64);
            Self::encode_string(buf, &header.value);
            return;
        }
        // Literal Field Line Without Name Reference
        // 0 0 1 0 0 x x x (prefix 3)
        Self::encode_integer(buf, 0x20, 3, header.name.len() as u64);
        buf.put_slice(header.name.as_bytes());
        Self::encode_string(buf, &header.value);
    }
    fn encode_string<B: BufMut>(buf: &mut B, s: &str) {
        // Format: H (0) | Length (7)
        let bytes = s.as_bytes();
        Self::encode_integer(buf, 0x00, 7, bytes.len() as u64);
        buf.put_slice(bytes);
    }
    fn encode_integer<B: BufMut>(buf: &mut B, prefix: u8, prefix_len: u8, mut value: u64) {
        let max_prefix = (1 << prefix_len) - 1;
        if value < max_prefix {
            buf.put_u8(prefix | (value as u8));
        } else {
            buf.put_u8(prefix | (max_prefix as u8));
            value -= max_prefix;
            while value >= 128 {
                buf.put_u8((value % 128 + 128) as u8);
                value /= 128;
            }
            buf.put_u8(value as u8);
        }
    }
}
/// QPACK Decoder (simplified)
pub struct QpackDecoder;
impl QpackDecoder {
    /// Decode a QPACK-encoded header block
    pub fn decode(mut data: Bytes) -> Result<Vec<Header>> {
        let mut headers = Vec::new();
        if data.remaining() < 2 {
            return Ok(headers);
        }
        // Skip Required Insert Count and Delta Base
        let _ric = data.get_u8();
        let _delta_base = data.get_u8();
        while data.has_remaining() {
            let first = data.get_u8();
            if first & 0x80 != 0 {
                // Indexed field line (static table reference)
                let idx = (first & 0x3f) as usize;
                if let Some((_, name, value)) = STATIC_TABLE.get(idx) {
                    headers.push(Header::new(*name, *value));
                }
            } else if first & 0x40 != 0 {
                // Literal with name reference
                let idx = (first & 0x0f) as usize;
                let value = Self::decode_string(&mut data)?;
                if let Some((_, name, _)) = STATIC_TABLE.get(idx) {
                    headers.push(Header::new(*name, value));
                }
            } else if first & 0x20 != 0 {
                // Literal without name reference
                let name = Self::decode_string(&mut data)?;
                let value = Self::decode_string(&mut data)?;
                headers.push(Header::new(name, value));
            } else {
                // Skip unknown patterns
                break;
            }
        }
        Ok(headers)
    }
    fn decode_string<B: Buf>(buf: &mut B) -> Result<String> {
        if !buf.has_remaining() {
            return Ok(String::new());
        }
        let first = buf.get_u8();
        let huffman = first & 0x80 != 0;
        let mut length = (first & 0x7f) as usize;
        if length == 0x7f && buf.has_remaining() {
            length += buf.get_u8() as usize;
        }
        if buf.remaining() < length {
            return Err(Error::BufferTooShort {
                needed: length,
                have: buf.remaining(),
            });
        }
        let data = buf.copy_to_bytes(length);
        
        if huffman {
            // Huffman decoding not implemented, return as-is
            Ok(String::from_utf8_lossy(&data).to_string())
        } else {
            Ok(String::from_utf8_lossy(&data).to_string())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encode_decode_static() {
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":status", "200"),
        ];
        let encoded = QpackEncoder::encode(&headers);
        let decoded = QpackDecoder::decode(encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], Header::new(":method", "GET"));
        assert_eq!(decoded[1], Header::new(":scheme", "https"));
        assert_eq!(decoded[2], Header::new(":status", "200"));
    }
    #[test]
    fn test_encode_decode_literal() {
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new("x-custom-header", "custom-value"),
        ];
        let encoded = QpackEncoder::encode(&headers);
        let decoded = QpackDecoder::decode(encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[1].name, "x-custom-header");
        assert_eq!(decoded[1].value, "custom-value");
    }
    #[test]
    fn test_common_headers() {
        let headers = vec![
            Header::new(":status", "200"),
            Header::new("content-type", "text/html; charset=utf-8"),
            Header::new("content-length", "1234"),
        ];
        let encoded = QpackEncoder::encode(&headers);
        println!("Encoded {} headers into {} bytes", headers.len(), encoded.len());
        
        let decoded = QpackDecoder::decode(encoded).unwrap();
        assert_eq!(decoded.len(), 3);
    }
}