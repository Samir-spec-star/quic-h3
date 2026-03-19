use super::recovery::{RecoveryManager, SentPacket, RecoveryStats};
use std::net::SocketAddr;
use std::time::Instant;
use bytes::Bytes;
use crate::Result;
use super::packet::ConnectionId;
use super::crypto::{ConnectionSecrets, derive_initial_secrets, generate_connection_id};
use super::streams::StreamManager;
/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Initial,
    Handshake,
    Connected,
    Closing,
    Closed,
}
/// Role in the connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}
/// A QUIC connection
#[derive(Debug)]
pub struct Connection {
    pub role: Role,
    pub state: ConnectionState,
    pub local_cid: ConnectionId,
    pub remote_cid: ConnectionId,
    pub remote_addr: SocketAddr,
    pub initial_secrets: Option<ConnectionSecrets>,
    pub next_packet_number: u64,
    pub highest_received: u64,
    pub pending_acks: Vec<u64>,
    pub created_at: Instant,
    pub recovery: RecoveryManager,
    pub streams: StreamManager,
}

impl Connection {
    pub fn new_server(
        remote_addr: SocketAddr,
        remote_cid: ConnectionId,
    ) -> Result<Self> {
        let local_cid = ConnectionId::new(generate_connection_id(8))?;
        let initial_secrets = derive_initial_secrets(remote_cid.as_bytes())?;
        Ok(Self {
            role: Role::Server,
            state: ConnectionState::Initial,
            local_cid,
            remote_cid,
            remote_addr,
            initial_secrets: Some(initial_secrets),
            next_packet_number: 0,
            highest_received: 0,
            pending_acks: Vec::new(),
            created_at: Instant::now(),
            streams: StreamManager::new(Role::Server),
            recovery: RecoveryManager::new(),
        })
    }
    pub fn new_client(remote_addr: SocketAddr) -> Result<Self> {
        let local_cid = ConnectionId::new(generate_connection_id(8))?;
        let remote_cid = ConnectionId::new(generate_connection_id(8))?;
        let initial_secrets = derive_initial_secrets(remote_cid.as_bytes())?;
        Ok(Self {
            role: Role::Client,
            state: ConnectionState::Initial,
            local_cid,
            remote_cid,
            remote_addr,
            initial_secrets: Some(initial_secrets),
            next_packet_number: 0,
            highest_received: 0,
            pending_acks: Vec::new(),
            created_at: Instant::now(),
            streams: StreamManager::new(Role::Client),
            recovery: RecoveryManager::new(),
        })
    }
    pub fn next_pn(&mut self) -> u64 {
        let pn = self.next_packet_number;
        self.next_packet_number += 1;
        pn
    }
    pub fn record_received(&mut self, packet_number: u64) {
        if packet_number > self.highest_received {
            self.highest_received = packet_number;
        }
        self.pending_acks.push(packet_number);
    }
    pub fn transition(&mut self, new_state: ConnectionState) {
        tracing::info!(
            "Connection {:?} transitioning from {:?} to {:?}",
            self.local_cid,
            self.state,
            new_state
        );
        self.state = new_state;
    }
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Connected
    }
    pub fn is_closed(&self) -> bool {
        self.state == ConnectionState::Closed
    }
    // NEW: Stream operations
    /// Open a new bidirectional stream
    pub fn open_bidi_stream(&mut self) -> Result<u64> {
        self.streams.open_bidi()
    }
    /// Open a new unidirectional stream
    pub fn open_uni_stream(&mut self) -> Result<u64> {
        self.streams.open_uni()
    }
    /// Send data on a stream
    pub fn send_stream_data(&mut self, stream_id: u64, data: Bytes) -> Result<()> {
        self.streams.send(stream_id, data)
    }
    /// Read data from a stream
    pub fn read_stream_data(&mut self, stream_id: u64, max_len: usize) -> Option<Bytes> {
        self.streams.read(stream_id, max_len)
    }
    /// Process received STREAM frame data
    pub fn receive_stream_data(
        &mut self,
        stream_id: u64,
        offset: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<()> {
        self.streams.receive(stream_id, offset, data, fin)
    }

    pub fn on_packet_sent(&mut self, packet_number: u64, size: usize, ack_eliciting: bool) {
        let sent_packet = SentPacket::new(packet_number, size, ack_eliciting);
        self.recovery.on_packet_sent(sent_packet);
    }

    //process an ACK frame
    pub fn on_ack_received(&mut self, largest_acked: u64, ack_delay_ms: u64) {
        use std::time::Duration;
        let ack_delay = Duration::from_micros(ack_delay_ms);
        //simplified: ack all packets up to largest_acked
        let ranges = vec![(0, largest_acked)];
        self.recovery.on_ack_received(largest_acked, ack_delay, &ranges);
    }

    //get packets that need retransmission
    pub fn get_lost_packets(&mut self) -> Vec<SentPacket> {
        self.recovery.get_lost_packets()
    }

    //check if we can send more data
    pub fn can_send(&self) -> bool {
        self.recovery.can_send()
    }

    //get recovery stats
    pub fn recovery_stats(&self) -> RecoveryStats {
        self.recovery.stats()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_new_server_connection() {
        let addr = "127.0.0.1:4433".parse().unwrap();
        let remote_cid = ConnectionId::new(vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        
        let conn = Connection::new_server(addr, remote_cid).unwrap();
        
        assert_eq!(conn.role, Role::Server);
        assert_eq!(conn.state, ConnectionState::Initial);
        assert!(conn.initial_secrets.is_some());
        assert_eq!(conn.streams.active_count(), 0);
    }
    #[test]
    fn test_stream_operations() {
        let addr = "127.0.0.1:4433".parse().unwrap();
        let mut conn = Connection::new_client(addr).unwrap();
        
        let stream_id = conn.open_bidi_stream().unwrap();
        assert_eq!(stream_id, 0);
        
        conn.send_stream_data(stream_id, Bytes::from("hello")).unwrap();
    }
}
