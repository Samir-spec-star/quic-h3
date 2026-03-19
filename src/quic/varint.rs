use crate::{Error, Result};
use bytes::{Buf, BufMut};

pub const MAX_VARINT: u64 = (1 << 62) - 1;

pub fn read_varint<B: Buf>(buf: &mut B) -> Result<u64> {
    if buf.remaining() < 1 {
        return Err(Error::BufferTooShort {
            needed: 1,
            have: buf.remaining(),
        });
    }

    let first_byte = buf.chunk()[0];

    let prefix = first_byte >> 6;
    let length = 1 << prefix;

    if buf.remaining() < length {
        return Err(Error::BufferTooShort {
            needed: length,
            have: buf.remaining(),
        });
    }

    let value = match length {
        1 => buf.get_u8() as u64 & 0x3f,
        2 => buf.get_u16() as u64 & 0x3fff,
        4 => buf.get_u32() as u64 & 0x3fff_ffff,
        8 => buf.get_u64() & 0x3fff_ffff_ffff_ffff,
        _ => {
            return Err(Error::InvalidVarint(format!(
                "Invalid varint prefix: {}",
                prefix
            )));
        }
    };

    Ok(value)
}

pub fn write_varint<B: BufMut>(buf: &mut B, value: u64) -> Result<()> {
    if value > MAX_VARINT {
        return Err(Error::InvalidVarint(format!(
            "Value {} exceeds max varint value {}",
            value, MAX_VARINT
        )));
    }

    if value <= 63 {
        buf.put_u8(value as u8);
    } else if value <= 16383 {
        // 2 bytes: prefix 01, 14-bit value
        buf.put_u16(0x4000 | value as u16);
    } else if value <= 1_073_741_823 {
        // 4 bytes: prefix 10, 30-bit value
        buf.put_u32(0x8000_0000 | value as u32);
    } else {
        // 8 bytes: prefix 11, 62-bit value
        buf.put_u64(0xc000_0000_0000_0000 | value);
    }
    Ok(())
}
//returns the number fo bytes needed to encode a value as a varint
pub fn varint_len(value: u64) -> usize {
    if value <= 63 {
        1
    } else if value <= 16383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else {
        8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
    #[test]
    fn test_read_1_byte_varint() {
        // Value 37 (0x25) - single byte
        let mut buf = Bytes::from_static(&[0x25]);
        assert_eq!(read_varint(&mut buf).unwrap(), 37);
    }
    #[test]
    fn test_read_2_byte_varint() {
        // Value 15293 - two bytes (prefix 01)
        let mut buf = Bytes::from_static(&[0x7b, 0xbd]);
        assert_eq!(read_varint(&mut buf).unwrap(), 15293);
    }
    #[test]
    fn test_read_4_byte_varint() {
        // Value 494878333 - four bytes (prefix 10)
        let mut buf = Bytes::from_static(&[0x9d, 0x7f, 0x3e, 0x7d]);
        assert_eq!(read_varint(&mut buf).unwrap(), 494878333);
    }
    #[test]
    fn test_read_8_byte_varint() {
        // Value 151288809941952652 - eight bytes (prefix 11)
        let mut buf = Bytes::from_static(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
        assert_eq!(read_varint(&mut buf).unwrap(), 151288809941952652);
    }
    #[test]
    fn test_write_1_byte_varint() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 37).unwrap();
        assert_eq!(&buf[..], &[0x25]);
    }
    #[test]
    fn test_write_2_byte_varint() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 15293).unwrap();
        assert_eq!(&buf[..], &[0x7b, 0xbd]);
    }
    #[test]
    fn test_roundtrip() {
        let test_values = [0, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824];

        for &value in &test_values {
            let mut buf = BytesMut::new();
            write_varint(&mut buf, value).unwrap();

            let mut read_buf = buf.freeze();
            let decoded = read_varint(&mut read_buf).unwrap();

            assert_eq!(value, decoded, "Roundtrip failed for value {}", value);
        }
    }
    #[test]
    fn test_varint_len() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(63), 1);
        assert_eq!(varint_len(64), 2);
        assert_eq!(varint_len(16383), 2);
        assert_eq!(varint_len(16384), 4);
        assert_eq!(varint_len(1_073_741_823), 4);
        assert_eq!(varint_len(1_073_741_824), 8);
    }
    #[test]
    fn test_buffer_too_short() {
        let mut buf = Bytes::from_static(&[]);
        assert!(matches!(
            read_varint(&mut buf),
            Err(Error::BufferTooShort { .. })
        ));
    }
}
