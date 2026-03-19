use bytes::Bytes;
use quic_h3::h3::{H3Frame, QpackDecoder, QpackEncoder};
use quic_h3::{Response, Server, ServerConfig};
use tracing_subscriber;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let config = ServerConfig {
        bind_addr: "127.0.0.1:4433".parse()?,
        max_connections: 100,
    };
    let mut server = Server::bind(config).await?;

    server.on_stream_data(|stream_id, data| {
        println!("\n Stream {}: Received {} bytes", stream_id, data.len());

        // Try to parse as HTTP/3 frame
        let mut buf = data.clone();
        match H3Frame::parse(&mut buf) {
            Ok(H3Frame::Headers(encoded)) => {
                println!("    HEADERS frame received");
                if let Ok(headers) = QpackDecoder::decode(encoded) {
                    for h in &headers {
                        println!("      {}: {}", h.name, h.value);
                    }
                }

                // Send a response
                let response = Response::ok()
                    .header("server", "quic-h3/0.1.0")
                    .body_html("<h1>Hello from HTTP/3!</h1>");

                let headers = response.to_headers();
                let encoded = QpackEncoder::encode(&headers);

                let mut response_buf = bytes::BytesMut::new();
                H3Frame::write_headers(&mut response_buf, &encoded);
                H3Frame::write_data(&mut response_buf, &response.body);

                return Some(response_buf.freeze());
            }
            Ok(H3Frame::Data(body)) => {
                println!("    DATA frame: {} bytes", body.len());
                println!("    Content: {:?}", String::from_utf8_lossy(&body));
            }
            Ok(frame) => {
                println!("    Other frame: {:?}", frame);
            }
            Err(_) => {
                // Not an HTTP/3 frame, treat as raw data
                println!("    Raw data: {:?}", String::from_utf8_lossy(&data));

                // Echo it back
                let msg = format!("Echo: {}", String::from_utf8_lossy(&data));
                return Some(Bytes::from(msg));
            }
        }

        None
    });

    println!("\n Server listening on 127.0.0.1:4433");
    println!("   Press Ctrl+C to stop\n");
    server.run().await?;
    Ok(())
}
