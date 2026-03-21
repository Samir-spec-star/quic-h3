use std::net::SocketAddr;
use tokio::net::UdpSocket;
use bytes::BytesMut;
use tracing::{info, error};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .init();
    info!("Starting QUIC/HTTP3 Test Client...");
    let _socket = UdpSocket::bind("0.0.0.0:0").await?;
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;
    info!("Connecting to Server at {}", server_addr);
    for client_id in 1..=3 {
        let socket_clone = UdpSocket::bind("0.0.0.0:0").await?; 
        let srv_addr = server_addr.clone();
        tokio::spawn(async move {
            info!("[Client {}] Generating QUIC Packet...", client_id);

            let start = std::time::Instant::now();
                     let mut packet = BytesMut::new();
            
            let fake_cid = vec![
                rand::random(), rand::random(), rand::random(), rand::random(), rand::random(), rand::random(), rand::random(), rand::random()
            ];
            
            let header = quic_h3::quic::LongHeader {
                packet_type: quic_h3::quic::LongPacketType::Initial,
                version: quic_h3::quic::version::QUIC_V1,
                dcid: quic_h3::quic::ConnectionId::new(fake_cid).unwrap(),
                scid: quic_h3::quic::ConnectionId::new(vec![8, 7, 6, 5, 4, 3, 2, 1]).unwrap(),
            };
            header.write(&mut packet);
            
            let payload = format!("Hello World from Client {}!", client_id);
            let stream_id = (client_id as u64) * 4;
            quic_h3::quic::Frame::write_stream(&mut packet, stream_id, payload.as_bytes(), true).unwrap();            
            
            if let Err(e) = socket_clone.send_to(&packet, srv_addr).await {
                error!("[Client {}] Failed to send packet: {}", client_id, e);
                return;
            }

            let mut recv_buf = vec![0u8; 1024];
            match tokio::time::timeout(std::time::Duration::from_secs(2), socket_clone.recv_from(&mut recv_buf)).await {
                Ok(Ok((len, _))) => {
                    let latency = start.elapsed();
                    info!("[Client {}] Latency: {:2?}", client_id, latency);
                
                    let response = String::from_utf8_lossy(&recv_buf[..len]);
                    info!("[Client {}]  Received Server Response: {}", client_id, response);
                }
                Ok(Err(e)) => error!("[Client {}] Error receiving: {}", client_id, e),
                Err(_) => error!("[Client {}]  Timeout waiting for server response", client_id),
            }
        });
    }
    
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    info!("Client test complete.");
    Ok(())
}