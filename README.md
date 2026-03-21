# quic-h3: A From-Scratch QUIC & HTTP/3 Stack in Rust

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active_development-brightgreen.svg)]()

> **quic-h3** is an educational, pure-Rust implementation of the QUIC transport protocol and HTTP/3 application layer built entirely from scratch. 

This project explores the low-level mechanics of modern web networking by manually parsing packet frames, handling UDP sockets, deriving cryptographic keys, and executing advanced stream multiplexing—**without relying on fully-packaged transport libraries like endpoint or quinn.**

##  Core Features Designed From Scratch

###  1. Custom QUIC Transport (RFC 9000 & 9002)
*   **Packet Parsing:** Manual ingestion of QUIC Initial, Handshake, and 1-RTT packets.
*   **Variable-Length Integer Encoding:** Low-level varint byte-manipulation.
*   **Reliability:** Custom RTT estimation, packet loss detection, and retransmission.
*   **Congestion Control:** Simplified Cubic-like window scaling (`cwnd` and `ssthresh`).
*   **Stream Multiplexing:** Independent bidirectional stream handling over a single UDP socket to prevent head-of-line blocking.

###  2. Cryptography & TLS 1.3 Handshake (RFC 9001)
*   **HKDF Key Derivation:** Custom derivations of Initial, Handshake, and 1-RTT secrets using the `ring` crate.
*   **Nonce Generation:** Synchronization of packet numbers with AEAD nonces.

###  3. HTTP/3 & QPACK (RFC 9114 & 9204)
*   **Frame Manipulation:** Support for `DATA`, `HEADERS`, `SETTINGS`, and `GOAWAY` frames.
*   **QPACK Compression:** Manual bit-masking and prefix decoding for HTTP headers against the QPACK static table.
*   **API Types:** Fully typed `Request` and `Response` abstractions.

---

##  Architecture

```text
┌────────────────────────────────────────┐
│           Application Layer            │
│   (Custom routing & request handlers)  │
├────────────────────────────────────────┤
│              HTTP/3 Layer              │
│   • QPACK Header Compression           │
│   • HEADERS/DATA Frames                │
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

## Quick Start

Ensure you have Rust installed. Clone the repository and run the pre-configured HTTP/3 echo server:

```bash
git clone https://github.com/yourusername/quic-h3.git
cd quic-h3
cargo run
```

### Output Example
```text
╔═══════════════════════════════════════╗
║     QUIC HTTP/3 Server v0.1.0         ║
║  Phase 5: HTTP/3 Protocol Layer       ║
╠═══════════════════════════════════════╣
║  Features:                            ║
║  ✓ QUIC Transport (RFC 9000)          ║
║  ✓ Stream Multiplexing                ║
║  ✓ Loss Detection & Recovery          ║
║  ✓ Congestion Control                 ║
║  ✓ HTTP/3 Frames (RFC 9114)           ║
║  ✓ QPACK Header Compression           ║
╚═══════════════════════════════════════╝

 Server listening on 127.0.0.1:4433
```

##  Testing

The codebase includes **50+ unit tests** validating protocol correctness piece-by-piece:

```bash
# Run the test suite
cargo test
```
Tests cover:
- Variable-length integer edge-cases.
- Frame parsing and byte-by-byte serialization.
- QPACK bit-masking correctness.
- Cryptographic key derivations.

## 📄 License
This project is licensed under the MIT License.
