use crate::{Error, Result};
use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
/// Stream type based on the last 2 bits of the stream ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Client-initiated, bidirectional (0b00)
    ClientBidi,
    /// Server-initiated, bidirectional (0b01)
    ServerBidi,
    /// Client-initiated, unidirectional (0b10)
    ClientUni,
    /// Server-initiated, unidirectional (0b11)
    ServerUni,
}
impl StreamType {
    /// Get the stream type from a stream ID
    pub fn from_id(stream_id: u64) -> Self {
        match stream_id & 0x03 {
            0 => StreamType::ClientBidi,
            1 => StreamType::ServerBidi,
            2 => StreamType::ClientUni,
            3 => StreamType::ServerUni,
            _ => unreachable!(),
        }
    }
    /// Check if this is a bidirectional stream
    pub fn is_bidi(&self) -> bool {
        matches!(self, StreamType::ClientBidi | StreamType::ServerBidi)
    }
    /// Check if this is a unidirectional stream
    pub fn is_uni(&self) -> bool {
        !self.is_bidi()
    }
    /// Check if this stream is initiated by the client
    pub fn is_client_initiated(&self) -> bool {
        matches!(self, StreamType::ClientBidi | StreamType::ClientUni)
    }
    /// Check if this stream is initiated by the server
    pub fn is_server_initiated(&self) -> bool {
        !self.is_client_initiated()
    }
}
/// Stream state (sending side)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    /// Stream is open for sending
    Ready,
    /// Data is being sent
    Send,
    /// All data sent, waiting for acknowledgment
    DataSent,
    /// FIN has been acknowledged
    DataRecvd,
    /// Stream was reset
    ResetSent,
    /// Reset was acknowledged
    ResetRecvd,
}
/// Stream state (receiving side)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    /// Waiting for data
    Recv,
    /// Received some data, may have gaps
    SizeKnown,
    /// All data received
    DataRecvd,
    /// All data has been read by the application
    DataRead,
    /// Stream was reset by peer
    ResetRecvd,
    /// Reset has been read by application
    ResetRead,
}
/// Flow control state for a stream or connection
#[derive(Debug, Clone)]
pub struct FlowControl {
    /// Maximum data we're allowed to send
    pub max_data: u64,
    /// Data we've sent so far
    pub data_sent: u64,
    /// Maximum data we're willing to receive
    pub max_data_recv: u64,
    /// Data we've received so far
    pub data_recv: u64,
}
impl FlowControl {
    /// Create new flow control with initial limits
    pub fn new(initial_max_data: u64) -> Self {
        Self {
            max_data: initial_max_data,
            data_sent: 0,
            max_data_recv: initial_max_data,
            data_recv: 0,
        }
    }
    /// Check how many bytes we can send
    pub fn available_send(&self) -> u64 {
        self.max_data.saturating_sub(self.data_sent)
    }
    /// Check how many bytes we can receive
    pub fn available_recv(&self) -> u64 {
        self.max_data_recv.saturating_sub(self.data_recv)
    }
    /// Record that we sent data
    pub fn add_sent(&mut self, bytes: u64) {
        self.data_sent += bytes;
    }
    /// Record that we received data
    pub fn add_recv(&mut self, bytes: u64) {
        self.data_recv += bytes;
    }
    /// Update the peer's max data (from MAX_STREAM_DATA frame)
    pub fn update_max_send(&mut self, new_max: u64) {
        if new_max > self.max_data {
            self.max_data = new_max;
        }
    }
    /// Check if we're blocked from sending
    pub fn is_blocked(&self) -> bool {
        self.data_sent >= self.max_data
    }
}
/// A buffer segment with its offset
#[derive(Debug, Clone)]
pub struct BufferSegment {
    pub offset: u64,
    pub data: Bytes,
}
/// Ordered receive buffer that handles out-of-order data
#[derive(Debug, Default)]
pub struct RecvBuffer {
    /// Segments received (may be out of order)
    segments: VecDeque<BufferSegment>,
    /// Next offset we expect to read
    read_offset: u64,
    /// Whether FIN has been received
    fin_received: bool,
    /// Offset of the FIN (if received)
    fin_offset: Option<u64>,
}
impl RecvBuffer {
    pub fn new() -> Self {
        Self::default()
    }
    /// Insert data at a specific offset
    pub fn insert(&mut self, offset: u64, data: Bytes, fin: bool) {
        if data.is_empty() && !fin {
            return;
        }
        // Insert in sorted order by offset
        let segment = BufferSegment { offset, data };

        let pos = self
            .segments
            .iter()
            .position(|s| s.offset > offset)
            .unwrap_or(self.segments.len());

        self.segments.insert(pos, segment);
        if fin {
            self.fin_received = true;
            self.fin_offset = Some(offset);
        }
    }
    /// Read contiguous data from the buffer
    pub fn read(&mut self, max_len: usize) -> Option<Bytes> {
        let mut result = BytesMut::new();

        while let Some(segment) = self.segments.front() {
            // Check if this segment is next in order
            if segment.offset > self.read_offset {
                // Gap in data, can't read further
                break;
            }
            // Check if we've already read past this segment
            if segment.offset + segment.data.len() as u64 <= self.read_offset {
                // Already read, remove it
                self.segments.pop_front();
                continue;
            }
            // Calculate how much of this segment we can use
            let skip = (self.read_offset - segment.offset) as usize;
            let available = segment.data.len() - skip;
            let to_read = available.min(max_len - result.len());
            result.extend_from_slice(&segment.data[skip..skip + to_read]);
            self.read_offset += to_read as u64;
            if skip + to_read >= segment.data.len() {
                // Consumed entire segment
                self.segments.pop_front();
            }
            if result.len() >= max_len {
                break;
            }
        }
        if result.is_empty() {
            None
        } else {
            Some(result.freeze())
        }
    }
    /// Check if all data has been received (including FIN)
    pub fn is_complete(&self) -> bool {
        if let Some(fin_offset) = self.fin_offset {
            self.read_offset >= fin_offset && self.segments.is_empty()
        } else {
            false
        }
    }
    /// Check if there's data ready to read
    pub fn has_data(&self) -> bool {
        if let Some(segment) = self.segments.front() {
            segment.offset <= self.read_offset
        } else {
            false
        }
    }
}
/// Send buffer for outgoing data
#[derive(Debug, Default)]
pub struct SendBuffer {
    /// Data waiting to be sent
    pending: VecDeque<Bytes>,
    /// Current offset (total bytes queued)
    offset: u64,
    /// FIN queued
    fin_queued: bool,
}
impl SendBuffer {
    pub fn new() -> Self {
        Self::default()
    }
    /// Queue data to be sent
    pub fn push(&mut self, data: Bytes) {
        self.offset += data.len() as u64;
        self.pending.push_back(data);
    }
    /// Queue FIN (end of stream)
    pub fn push_fin(&mut self) {
        self.fin_queued = true;
    }
    /// Get pending data to send (up to max_len bytes)
    pub fn peek(&self, max_len: usize) -> Option<Bytes> {
        if let Some(data) = self.pending.front() {
            let len = data.len().min(max_len);
            Some(data.slice(0..len))
        } else {
            None
        }
    }
    /// Mark bytes as sent (remove from pending)
    pub fn consume(&mut self, len: usize) {
        while len > 0 && !self.pending.is_empty() {
            if let Some(front) = self.pending.front_mut() {
                if front.len() <= len {
                    self.pending.pop_front();
                } else {
                    *front = front.slice(len..);
                    break;
                }
            }
        }
    }
    /// Check if FIN should be sent
    pub fn should_send_fin(&self) -> bool {
        self.fin_queued && self.pending.is_empty()
    }
    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    /// Get total bytes pending
    pub fn pending_len(&self) -> usize {
        self.pending.iter().map(|b| b.len()).sum()
    }
}
/// A QUIC stream
#[derive(Debug)]
pub struct Stream {
    /// Stream ID
    pub id: u64,
    /// Stream type
    pub stream_type: StreamType,
    /// Send state
    pub send_state: SendState,
    /// Receive state
    pub recv_state: RecvState,
    /// Send buffer
    pub send_buffer: SendBuffer,
    /// Receive buffer
    pub recv_buffer: RecvBuffer,
    /// Flow control for this stream
    pub flow_control: FlowControl,
    /// Offset for next STREAM frame to send
    pub send_offset: u64,
}
impl Stream {
    /// Create a new stream
    pub fn new(id: u64, initial_max_data: u64) -> Self {
        let stream_type = StreamType::from_id(id);

        Self {
            id,
            stream_type,
            send_state: SendState::Ready,
            recv_state: RecvState::Recv,
            send_buffer: SendBuffer::new(),
            recv_buffer: RecvBuffer::new(),
            flow_control: FlowControl::new(initial_max_data),
            send_offset: 0,
        }
    }
    /// Queue data to send on this stream
    pub fn send(&mut self, data: Bytes) -> Result<()> {
        if !self.can_send() {
            return Err(Error::InvalidPacket(
                "Cannot send on this stream".to_string(),
            ));
        }
        self.send_buffer.push(data);
        self.send_state = SendState::Send;
        Ok(())
    }
    /// Queue FIN to close our send side
    pub fn finish(&mut self) -> Result<()> {
        if !self.can_send() {
            return Err(Error::InvalidPacket(
                "Cannot finish this stream".to_string(),
            ));
        }
        self.send_buffer.push_fin();
        Ok(())
    }
    /// Receive data on this stream
    pub fn receive(&mut self, offset: u64, data: Bytes, fin: bool) -> Result<()> {
        if !self.can_recv() {
            return Err(Error::InvalidPacket(
                "Cannot receive on this stream".to_string(),
            ));
        }
        self.flow_control.add_recv(data.len() as u64);
        self.recv_buffer.insert(offset, data, fin);

        if fin {
            self.recv_state = RecvState::SizeKnown;
        }
        Ok(())
    }
    /// Read received data
    pub fn read(&mut self, max_len: usize) -> Option<Bytes> {
        self.recv_buffer.read(max_len)
    }
    /// Check if we can send on this stream
    pub fn can_send(&self) -> bool {
        self.stream_type.is_bidi() || !self.stream_type.is_client_initiated()
        // TODO: Check based on role (client/server)
    }
    /// Check if we can receive on this stream
    pub fn can_recv(&self) -> bool {
        self.stream_type.is_bidi() || self.stream_type.is_client_initiated()
        // TODO: Check based on role
    }
    /// Check if stream has data to send
    pub fn has_pending_data(&self) -> bool {
        !self.send_buffer.is_empty() || self.send_buffer.should_send_fin()
    }
    /// Check if stream is fully closed
    pub fn is_closed(&self) -> bool {
        matches!(
            self.send_state,
            SendState::DataRecvd | SendState::ResetRecvd
        ) && matches!(self.recv_state, RecvState::DataRead | RecvState::ResetRead)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_stream_type_from_id() {
        assert_eq!(StreamType::from_id(0), StreamType::ClientBidi);
        assert_eq!(StreamType::from_id(4), StreamType::ClientBidi);
        assert_eq!(StreamType::from_id(1), StreamType::ServerBidi);
        assert_eq!(StreamType::from_id(2), StreamType::ClientUni);
        assert_eq!(StreamType::from_id(3), StreamType::ServerUni);
    }
    #[test]
    fn test_flow_control() {
        let mut fc = FlowControl::new(1000);

        assert_eq!(fc.available_send(), 1000);

        fc.add_sent(300);
        assert_eq!(fc.available_send(), 700);

        fc.update_max_send(2000);
        assert_eq!(fc.available_send(), 1700);
    }
    #[test]
    fn test_recv_buffer_ordered() {
        let mut buf = RecvBuffer::new();

        buf.insert(0, Bytes::from("hello"), false);
        buf.insert(5, Bytes::from(" world"), true);

        let data = buf.read(20).unwrap();
        assert_eq!(&data[..], b"hello world");
    }
    #[test]
    fn test_recv_buffer_out_of_order() {
        let mut buf = RecvBuffer::new();

        // Receive second chunk first
        buf.insert(5, Bytes::from(" world"), false);

        // Can't read yet (gap)
        assert!(buf.read(20).is_none());

        // Receive first chunk
        buf.insert(0, Bytes::from("hello"), false);

        // Now we can read
        let data = buf.read(20).unwrap();
        assert_eq!(&data[..], b"hello world");
    }
    #[test]
    fn test_send_buffer() {
        let mut buf = SendBuffer::new();

        buf.push(Bytes::from("hello"));
        buf.push(Bytes::from(" world"));

        assert_eq!(buf.pending_len(), 11);

        let data = buf.peek(5).unwrap();
        assert_eq!(&data[..], b"hello");
    }
    #[test]
    fn test_stream_send_receive() {
        let mut stream = Stream::new(0, 10000);

        // Send data
        stream.send(Bytes::from("hello")).unwrap();
        assert!(stream.has_pending_data());

        // Receive data
        stream.receive(0, Bytes::from("world"), false).unwrap();

        let data = stream.read(10).unwrap();
        assert_eq!(&data[..], b"world");
    }
}
