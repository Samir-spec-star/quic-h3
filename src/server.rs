use crate::Result;
use crate::quic::{Connection, ConnectionId, Frame, LongHeader};
use bytes::{Buf, Bytes};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
/// QUIC Server configuration

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub max_connections: usize,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:4433".parse().unwrap(),
            max_connections: 1000,
        }
    }
}
/// Callback for handling stream data
pub type StreamHandler = Box<dyn Fn(u64, Bytes) -> Option<Bytes> + Send + Sync>;
/// QUIC Server
pub struct Server {
    config: ServerConfig,
    socket: UdpSocket,
    connections: Arc<Mutex<HashMap<ConnectionId, Connection>>>,
    stream_handler: Option<StreamHandler>,
}
impl Server {
    pub async fn bind(config: ServerConfig) -> Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;

        tracing::info!("QUIC server listening on {}", config.bind_addr);
        Ok(Self {
            config,
            socket,
            connections: Arc::new(Mutex::new(HashMap::new())),
            stream_handler: None,
        })
    }
    /// Set a handler for incoming stream data
    pub fn on_stream_data<F>(&mut self, handler: F)
    where
        F: Fn(u64, Bytes) -> Option<Bytes> + Send + Sync + 'static,
    {
        self.stream_handler = Some(Box::new(handler));
    }
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let mut buf = vec![0u8; 65535];
        loop {
            let (len, src_addr) = self.socket.recv_from(&mut buf).await?;
            let data = Bytes::copy_from_slice(&buf[..len]);

            tracing::debug!("Received {} bytes from {}", len, src_addr);

            let _server_clone = Arc::clone(&self);

            if let Err(e) = self.handle_packet(data, src_addr).await {
                tracing::warn!("Error handling packet from {}: {}", src_addr, e);
            }
        }
    }
    async fn handle_packet(&self, data: Bytes, src_addr: SocketAddr) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let first_byte = data[0];
        let is_long_header = first_byte & 0x80 != 0;
        if is_long_header {
            self.handle_long_header_packet(data, src_addr).await
        } else {
            self.handle_short_header_packet(data, src_addr).await
        }
    }
    async fn handle_long_header_packet(&self, mut data: Bytes, src_addr: SocketAddr) -> Result<()> {
        let header = LongHeader::parse(&mut data)?;

        tracing::info!(
            "Received {:?} packet from {} (DCID: {:?})",
            header.packet_type,
            src_addr,
            header.dcid
        );
        let mut connections = self.connections.lock().await;

        if !connections.contains_key(&header.dcid) {
            if connections.len() >= self.config.max_connections {
                tracing::warn!("Max connections reached");
                return Ok(());
            }
            let conn = Connection::new_server(src_addr, header.scid.clone())?;

            tracing::info!(
                "New connection from {}, assigned CID {:?}",
                src_addr,
                conn.local_cid
            );

            connections.insert(header.dcid.clone(), conn);
        }
        // Try to parse frames from the remaining data
        // (In real QUIC, we'd need to decrypt first)
        self.process_frames(&mut data, &header.dcid, &mut connections)
            .await?;
        Ok(())
    }
    async fn handle_short_header_packet(&self, data: Bytes, src_addr: SocketAddr) -> Result<()> {
        tracing::debug!(
            "Received short header packet from {}, {} bytes",
            src_addr,
            data.len()
        );
        Ok(())
    }
    /// Process frames from a packet payload
    async fn process_frames(
        &self,
        data: &mut Bytes,
        cid: &ConnectionId,
        connections: &mut HashMap<ConnectionId, Connection>,
    ) -> Result<()> {
        while data.has_remaining() {
            match Frame::parse(data) {
                Ok(frame) => {
                    tracing::debug!("Parsed frame: {:?}", frame);

                    if let Some(conn) = connections.get_mut(cid) {
                        self.handle_frame(conn, frame).await?;
                    }
                }
                Err(e) => {
                    tracing::debug!("Could not parse frame: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }
    /// Handle a single frame
    async fn handle_frame(&self, conn: &mut Connection, frame: Frame) -> Result<()> {
        match frame {
            Frame::Ping => {
                tracing::debug!("Received PING");
                // Should respond with ACK (handled elsewhere)
            }
            Frame::Stream(stream_frame) => {
                tracing::info!(
                    "Received STREAM frame: stream_id={}, offset={}, len={}, fin={}",
                    stream_frame.stream_id,
                    stream_frame.offset,
                    stream_frame.data.len(),
                    stream_frame.fin
                );
                // Process the stream data
                conn.receive_stream_data(
                    stream_frame.stream_id,
                    stream_frame.offset,
                    stream_frame.data.clone(),
                    stream_frame.fin,
                )?;
                // If we have a handler, call it
                if let Some(ref handler) = self.stream_handler {
                    if let Some(response) = handler(stream_frame.stream_id, stream_frame.data) {
                        conn.send_stream_data(stream_frame.stream_id, response.clone())?;

                        let mut resp_buff = bytes::BytesMut::new();
                        let header = LongHeader {
                            packet_type: crate::quic::LongPacketType::Initial,
                            version: crate::quic::packet::version::QUIC_V1,
                            dcid: conn.remote_cid.clone(),
                            scid: conn.local_cid.clone(), 
                        };
                        header.write(&mut resp_buff);
                        crate::quic::Frame::write_stream(&mut resp_buff, stream_frame.stream_id, &response, true)?;

                        self.send_to(&resp_buff, conn.remote_addr).await?;
                        tracing::info!("[Stream {} Transmitted respone to {}]", stream_frame.stream_id, conn.remote_addr);
                    }
                }
            }
            Frame::Ack(ack) => {
                tracing::debug!(
                    "Received ACK: largest={}, delay={}",
                    ack.largest_ack,
                    ack.ack_delay
                );

                //Process the ACK
                conn.on_ack_received(ack.largest_ack, ack.ack_delay);

                //check for lost packets that need retransmission
                let lost = conn.get_lost_packets();
                if !lost.is_empty() {
                    tracing::warn!("{} packets need retransmission", lost.len());
                }

                //log stats
                let stats = conn.recovery_stats();
                tracing::debug!(
                    "Recovery stats: rtt={:?}, cwnd={}, in_flight={}",
                    stats.smoothed_rtt,
                    stats.cwnd,
                    stats.bytes_in_flight
                );
            }
            Frame::ConnectionClose(close) => {
                tracing::info!(
                    "Received CONNECTION_CLOSE: error={}, reason={}",
                    close.error_code,
                    close.reason_phrase
                );
                conn.transition(crate::quic::ConnectionState::Closing);
            }
            _ => {
                tracing::debug!("Received frame: {:?}", frame);
            }
        }
        Ok(())
    }
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        self.socket.send_to(data, addr).await?;
        Ok(())
    }
}
