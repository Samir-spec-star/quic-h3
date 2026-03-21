use bytes::Bytes;
use quic_h3::h3::{H3Frame, QpackDecoder, QpackEncoder};
use quic_h3::{Response, Server, ServerConfig};
use tracing::{info, debug, warn};
use tracing_subscriber::{fmt, EnvFilter};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup Professional Logging
    // This adds colors, timestamps, and log levels (INFO, DEBUG, ERROR)
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_target(false) // Hides the module path for cleaner output
        .with_thread_ids(true) // Shows which async thread is handling the request
        .init();
   
    let config = ServerConfig {
        bind_addr: "127.0.0.1:4433".parse()?,
        max_connections: 100,
    };
    
    let mut server = Server::bind(config).await?;
    server.on_stream_data(|stream_id, data| {
        info!("[Stream {}] Received {} bytes of payload", stream_id, data.len());
        let mut buf = data.clone();
        match H3Frame::parse(&mut buf) {
            Ok(H3Frame::Headers(encoded)) => {
                info!("[Stream {}] HEADERS frame received", stream_id);
                if let Ok(headers) = QpackDecoder::decode(encoded) {
                    for h in &headers {
                        debug!("      {}: {}", h.name, h.value);
                    }
                }
                let response = Response::ok()
                    .header("server", "quic-h3/0.1.0")
                    .body_html("<h1>Hello from HTTP/3!</h1>");
                let headers = response.to_headers();
                let encoded = QpackEncoder::encode(&headers);
                let mut response_buf = bytes::BytesMut::new();
                H3Frame::write_headers(&mut response_buf, &encoded);
                H3Frame::write_data(&mut response_buf, &response.body);
                info!("[Stream {}] ✅ Sending HTTP/3 Response", stream_id);
                return Some(response_buf.freeze());
            }
            Ok(H3Frame::Data(body)) => {
                info!("[Stream {}] DATA frame: {} bytes", stream_id, body.len());
            }
            Ok(frame) => {
                debug!("[Stream {}] Other frame: {:?}", stream_id, frame);
            }
            Err(_) => {
                warn!("[Stream {}] Raw unformatted data received", stream_id);
                let msg = format!("Echo: {}", String::from_utf8_lossy(&data));
                return Some(Bytes::from(msg));
            }
        }
        None
    });
    info!("Server listening on 127.0.0.1:4433 (Press Ctrl+C to stop)");
    
    // Start the server loop
    std::sync::Arc::new(server).run().await?;
    Ok(())
}