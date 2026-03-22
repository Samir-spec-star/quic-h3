
# quic-h3: A From-Scratch QUIC & HTTP/3 Stack in Rust

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen.svg)]()

---

## Overview

**quic-h3** is an educational, from-scratch implementation of the QUIC transport protocol and HTTP/3 application layer written entirely in Rust.

This project explores the low-level mechanics of modern web networking by manually parsing packet frames, handling UDP sockets, deriving cryptographic keys, and executing advanced stream multiplexing—without relying on fully packaged transport libraries such as `quinn` or similar abstractions.

The implementation emphasizes transparency, control, and performance, providing a systems-level understanding of how modern web protocols operate internally.

---

## Objectives

* Understand QUIC as a UDP-based transport protocol
* Implement HTTP/3 framing and header compression (QPACK)
* Build transport-layer reliability without TCP
* Explore congestion control and multiplexed streams
* Measure performance using statistical benchmarking

---

## Architecture

```text id="arch1"
┌────────────────────────────────────────┐
│           Application Layer            │
│   (Custom routing & request handlers)  │
├────────────────────────────────────────┤
│              HTTP/3 Layer              │
│   • QPACK Header Compression           │
│   • HEADERS / DATA Frames              │
├────────────────────────────────────────┤
│            QUIC Transport              │
│   • Stream Multiplexing                │
│   • Loss Detection & Retransmission    │
│   • Cubic Congestion Control           │
│   • TLS 1.3 HKDF Key Expansion         │
├────────────────────────────────────────┤
│               UDP I/O                  │
└────────────────────────────────────────┘
```

---

## Core Features Designed From Scratch

### 1. High-Concurrency QUIC Transport (RFC 9000 & 9002)

* **Packet Handling**
  Manual ingestion and serialization of Initial, Handshake, and 1-RTT packets

* **Concurrency Model**
  Asynchronous task-per-packet execution using `tokio::spawn` for handling multiple parallel clients

* **Variable-Length Integer Encoding**
  Low-level varint encoding/decoding for protocol headers

* **Reliability Layer**
  Custom RTT estimation, packet loss detection, and retransmission logic

* **Congestion Control**
  Simplified Cubic-like congestion window scaling (`cwnd`, `ssthresh`)

* **Stream Multiplexing**
  Independent bidirectional streams over a single UDP connection to eliminate head-of-line blocking

---

### 2. Cryptography & TLS 1.3 Handshake (RFC 9001)

* **HKDF Key Derivation**
  Derivation of Initial, Handshake, and 1-RTT secrets using cryptographic primitives

* **Nonce Generation**
  Synchronization of packet numbers with AEAD nonces for secure packet encryption

---

### 3. HTTP/3 & QPACK (RFC 9114 & 9204)

* **Frame Handling**
  Support for DATA, HEADERS, SETTINGS, and GOAWAY frames

* **QPACK Compression**
  Static table-based header compression with bit-level prefix decoding

* **Logging & Observability**
  Structured tracing using `tracing-subscriber` for debugging protocol behavior

---

## Performance Benchmarks

Benchmarks were conducted using **Criterion.rs**, a statistical benchmarking framework for Rust.

### Compression Efficiency

| Metric                | Value     |
| --------------------- | --------- |
| Raw Header Size       | 167 bytes |
| QPACK Compressed Size | 129 bytes |
| Compression Ratio     | 23%       |

---

### Encoding Performance

| Metric          | Value                |
| --------------- | -------------------- |
| Iterations      | 100,000              |
| Total Time      | 135 ms               |
| Average Latency | ~1.35 µs             |
| Throughput      | ~738,877 encodes/sec |

---

![pdf_small](https://github.com/user-attachments/assets/f32360e2-4f69-4a62-950e-527996b0b177)
![regression_small](https://github.com/user-attachments/assets/057ac667-fdab-45c3-af36-73e53532404b)
![relative_pdf_small](https://github.com/user-attachments/assets/00884f62-d8c4-4b17-8cd2-d77edfe7998f)
![relative_regression_small](https://github.com/user-attachments/assets/65e455e0-dc29-47a9-9851-0b56c074d8ce)

---

### Methodology

* High-iteration statistical benchmarking using Criterion
* Focus on encoding latency and throughput
* Controlled local environment testing

---

## Project Structure

```text id="struct1"
/src        Core protocol implementation
/benches    Criterion benchmarking suite
/bin        Server and client executables
```

---

## Getting Started

### Prerequisites

* Rust (stable toolchain)

### Clone the Repository

```bash id="cmd1"
git clone https://github.com/Samir-spec-star/quic-h3
cd quic-h3
```

---

### Run the Server

```bash id="cmd2"
cargo run --bin quic-server
```

#### Example Output

```text id="out1"
QUIC HTTP/3 Server v0.1.0
Features:
- QUIC Transport (RFC 9000)
- Stream Multiplexing
- Loss Detection & Recovery
- Congestion Control
- HTTP/3 Frames
- QPACK Header Compression

Server listening on 127.0.0.1:4433
```

---

### Run the Client (Stress Test)

```bash id="cmd3"
cargo run --bin quic-client
```

This launches multiple concurrent clients to simulate load and measure RTT.

---

## Testing

The project includes a comprehensive test suite validating protocol components.

```bash id="cmd4"
cargo test
```

---

## Key Insights

* QPACK achieves meaningful compression (~23%) with low computational overhead
* Microsecond-level encoding latency enables high-throughput systems
* QUIC eliminates head-of-line blocking via stream multiplexing
* Implementing transport protocols reveals trade-offs between reliability, latency, and complexity

---

## Limitations

* Not production-ready
* Simplified congestion control model
* Limited QPACK dynamic table support
* No full TLS handshake integration for production security

---

## Future Work

* Multi-client scalability benchmarking
* End-to-end request-response latency measurement
* QUIC vs TCP comparative analysis
* Dynamic QPACK table implementation
* TLS 1.3 full integration

---

## Why This Project Matters

Very few developers implement transport protocols from scratch. This project demonstrates:

* Deep understanding of how UDP-based protocols achieve reliability
* Practical application of asynchronous concurrency in Rust
* Ability to translate complex RFC specifications into working systems
* Strong systems-level engineering and performance awareness

---

## License

This project is licensed under the MIT License.

---

## Author

Sameer Gupta
https://x.com/samir1672007
