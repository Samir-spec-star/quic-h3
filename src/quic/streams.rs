use std::collections::HashMap;
use bytes::Bytes;
use crate::{Error, Result};
use super::stream::{Stream, StreamType, FlowControl};
use super::connection::Role;
/// Default initial max stream data
const INITIAL_MAX_STREAM_DATA: u64 = 1_000_000; // 1 MB
/// Manages all streams for a connection
#[derive(Debug)]
pub struct StreamManager {
    /// All active streams
    streams: HashMap<u64, Stream>,
    /// Our role (client or server)
    role: Role,
    /// Next client-initiated bidirectional stream ID
    next_client_bidi: u64,
    /// Next server-initiated bidirectional stream ID
    next_server_bidi: u64,
    /// Next client-initiated unidirectional stream ID
    next_client_uni: u64,
    /// Next server-initiated unidirectional stream ID
    next_server_uni: u64,
    /// Connection-level flow control
    pub connection_flow: FlowControl,
}
impl StreamManager {
    /// Create a new stream manager
    pub fn new(role: Role) -> Self {
        Self {
            streams: HashMap::new(),
            role,
            next_client_bidi: 0,
            next_server_bidi: 1,
            next_client_uni: 2,
            next_server_uni: 3,
            connection_flow: FlowControl::new(10_000_000), // 10 MB connection level
        }
    }
    /// Open a new bidirectional stream (initiated by us)
    pub fn open_bidi(&mut self) -> Result<u64> {
        let stream_id = match self.role {
            Role::Client => {
                let id = self.next_client_bidi;
                self.next_client_bidi += 4;
                id
            }
            Role::Server => {
                let id = self.next_server_bidi;
                self.next_server_bidi += 4;
                id
            }
        };
        let stream = Stream::new(stream_id, INITIAL_MAX_STREAM_DATA);
        self.streams.insert(stream_id, stream);
        tracing::debug!("Opened bidirectional stream {}", stream_id);
        Ok(stream_id)
    }
    /// Open a new unidirectional stream (initiated by us)
    pub fn open_uni(&mut self) -> Result<u64> {
        let stream_id = match self.role {
            Role::Client => {
                let id = self.next_client_uni;
                self.next_client_uni += 4;
                id
            }
            Role::Server => {
                let id = self.next_server_uni;
                self.next_server_uni += 4;
                id
            }
        };
        let stream = Stream::new(stream_id, INITIAL_MAX_STREAM_DATA);
        self.streams.insert(stream_id, stream);
        tracing::debug!("Opened unidirectional stream {}", stream_id);
        Ok(stream_id)
    }
    /// Get or create a stream (for incoming data)
    pub fn get_or_create(&mut self, stream_id: u64) -> Result<&mut Stream> {
        if !self.streams.contains_key(&stream_id) {
            // Validate the stream ID based on initiator
            let stream_type = StreamType::from_id(stream_id);
            
            let is_peer_initiated = match self.role {
                Role::Client => stream_type.is_server_initiated(),
                Role::Server => stream_type.is_client_initiated(),
            };
            if !is_peer_initiated {
                // The peer is using a stream ID that we should initiate
                // This is only valid if we already opened it
                return Err(Error::InvalidPacket(format!(
                    "Invalid stream ID {} for peer",
                    stream_id
                )));
            }
            // Create the stream
            let stream = Stream::new(stream_id, INITIAL_MAX_STREAM_DATA);
            self.streams.insert(stream_id, stream);
            
            tracing::debug!("Created stream {} from peer", stream_id);
        }
        Ok(self.streams.get_mut(&stream_id).unwrap())
    }
    /// Get a stream by ID
    pub fn get(&self, stream_id: u64) -> Option<&Stream> {
        self.streams.get(&stream_id)
    }
    /// Get a mutable stream by ID
    pub fn get_mut(&mut self, stream_id: u64) -> Option<&mut Stream> {
        self.streams.get_mut(&stream_id)
    }
    /// Send data on a stream
    pub fn send(&mut self, stream_id: u64, data: Bytes) -> Result<()> {
        let stream = self.get_mut(stream_id)
            .ok_or_else(|| Error::InvalidPacket(format!("Stream {} not found", stream_id)))?;
        
        stream.send(data)
    }
    /// Receive data on a stream
    pub fn receive(&mut self, stream_id: u64, offset: u64, data: Bytes, fin: bool) -> Result<()> {
        let stream = self.get_or_create(stream_id)?;
        stream.receive(offset, data, fin)
    }
    /// Read data from a stream
    pub fn read(&mut self, stream_id: u64, max_len: usize) -> Option<Bytes> {
        self.get_mut(stream_id)?.read(max_len)
    }
    /// Get all streams with pending data to send
    pub fn streams_with_pending_data(&self) -> Vec<u64> {
        self.streams
            .iter()
            .filter(|(_, s)| s.has_pending_data())
            .map(|(id, _)| *id)
            .collect()
    }
    /// Close a stream
    pub fn close(&mut self, stream_id: u64) -> Result<()> {
        if let Some(stream) = self.get_mut(stream_id) {
            stream.finish()?;
        }
        Ok(())
    }
    /// Remove closed streams
    pub fn cleanup_closed(&mut self) {
        self.streams.retain(|id, stream| {
            if stream.is_closed() {
                tracing::debug!("Removing closed stream {}", id);
                false
            } else {
                true
            }
        });
    }
    /// Get the number of active streams
    pub fn active_count(&self) -> usize {
        self.streams.len()
    }
    /// Iterate over all streams
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &Stream)> {
        self.streams.iter()
    }
    /// Iterate mutably over all streams
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&u64, &mut Stream)> {
        self.streams.iter_mut()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_open_bidi_client() {
        let mut mgr = StreamManager::new(Role::Client);
        
        let id1 = mgr.open_bidi().unwrap();
        let id2 = mgr.open_bidi().unwrap();
        
        assert_eq!(id1, 0); // Client bidi starts at 0
        assert_eq!(id2, 4); // Next is +4
    }
    #[test]
    fn test_open_bidi_server() {
        let mut mgr = StreamManager::new(Role::Server);
        
        let id1 = mgr.open_bidi().unwrap();
        let id2 = mgr.open_bidi().unwrap();
        
        assert_eq!(id1, 1); // Server bidi starts at 1
        assert_eq!(id2, 5); // Next is +4
    }
    #[test]
    fn test_open_uni() {
        let mut mgr = StreamManager::new(Role::Client);
        
        let id1 = mgr.open_uni().unwrap();
        let id2 = mgr.open_uni().unwrap();
        
        assert_eq!(id1, 2); // Client uni starts at 2
        assert_eq!(id2, 6); // Next is +4
    }
    #[test]
    fn test_receive_creates_stream() {
        let mut mgr = StreamManager::new(Role::Server);
        
        // Client sends on stream 0 (client-initiated bidi)
        mgr.receive(0, 0, Bytes::from("hello"), false).unwrap();
        
        assert!(mgr.get(0).is_some());
    }
    #[test]
    fn test_send_and_read() {
        let mut mgr = StreamManager::new(Role::Client);
        
        let stream_id = mgr.open_bidi().unwrap();
        
        // Simulate receiving data on the stream
        mgr.receive(stream_id, 0, Bytes::from("response"), false).unwrap();
        
        let data = mgr.read(stream_id, 100).unwrap();
        assert_eq!(&data[..], b"response");
    }
}   