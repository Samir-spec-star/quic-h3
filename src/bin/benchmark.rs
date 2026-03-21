use std::time::Instant;
use quic_h3::h3::{Header, QpackEncoder};

fn main() {
    println!("quic-h3: performance benchmark");
     
    let headers = vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/api/v1/resource/user-data"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "api.example.com"),
        Header::new("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        Header::new("accept-encoding", "gzip, deflate, br, zstd"),
    ];
    let raw_size: usize = headers.iter().map(|h| h.name.len() + h.value.len()).sum();
    let encoded = QpackEncoder::encode(&headers);
    let compressed_size = encoded.len();
    println!("Compression Ratio:");
    println!("   Raw Header Size: {} bytes", raw_size);
    println!("   QPACK Size:      {} bytes", compressed_size);
    println!("   Saving:      {}%", 100 - (compressed_size * 100 / raw_size));
    println!();
    // 2 Encoding Speed Test 
    let iterations = 100_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = QpackEncoder::encode(&headers);
    }
    let duration = start.elapsed();
    println!("Encoding Speed:");
    println!("   Iterations:   {}", iterations);
    println!("   Total Time:   {:?}", duration);
    println!("   Avg per Enc:  {:?}", duration / iterations);
    println!("   TPS:          {:.0} encodes/sec", iterations as f64 / duration.as_secs_f64());
    
}