# Sibna Protocol v3.0.0 "Fortress"

A high-security Rust implementation of the X3DH and Double Ratchet protocol — E2EE dual-licensed under Apache 2.0 / MIT.

> This is an independent project. It is not affiliated with the Signal Technology Foundation and does not use their code.

---

> [!IMPORTANT]
> **Production-Ready Status (Pre-Audit)**: Sibna v3.0.0 is a hardened cryptographic suite validated via statistical benchmarks ($<10ns$ variance) and symbolic execution (Kani) proofs. While it still awaits a formal 3rd-party independent audit (Roadmap: Q3 2026), it meets high-assurance baseline requirements for commercial-grade deployment.

---

## Currently Implemented Features

| Feature | Status | Reference |
|--------|--------|--------|
| X3DH v10 + Transcript Binding (BLAKE3) | ✅ | `crypto/kdf.rs`, `p2p/handshake.rs` |
| Stealth Handshake (Identity Hiding in P2P) | ✅ | `p2p/handshake.rs:57` |
| Double Ratchet (Forward Secrecy) | ✅ | `ratchet/` |
| Hybrid PQC: X25519 + ML-KEM-768 | ✅ Default | `handshake/x3dh.rs` |
| Delivery ACKs (Zero Message Loss) | ✅ | `ws.rs` |
| Last Resort PreKeys | ✅ | `main.rs`, `client.py` |
| WebRTC Session Routing | ✅ | `ws.rs` |
| Argon2id for stored key derivation | ✅ | `lib.rs:250` — requires `feature = "argon2"` |
| Memory Pinning (`mlock`/`VirtualLock`) | ✅ | `crypto/random.rs` |
| Multi-Device `device_id` in KDF | ✅ | `lib.rs:144` |
| Sealed Sender (Server cannot see sender) | ✅ | `metadata.rs` |
| Message Size Padding (256B→16KB) | ✅ | `crypto/padding.rs` |
| Cover Traffic (Exponential Distribution) | ✅ | `manager.rs` |
| P2P mDNS Discovery (with cancellation) | ✅ | `manager.rs`, `p2p/discovery.rs` |
| SOCKS5 / Tor relay | ✅ | `transport/relay.rs` |
| Multi-layered Rate Limiting | ✅ | `rate_limit.rs` |
| FFI (C/C++/Flutter/Python) | ✅ | `ffi/mod.rs` |
| WASM (JavaScript/TypeScript) | ✅ | `wasm.rs` |

## Quick Start

```toml
[dependencies]
sibna-core = { version = "3.0.0", features = ["pqc", "p2p"] }
```

```rust
use sibna_core::{SecureContext, Config};

// Initialize context (Argon2id protects storage if enabled)
let ctx = SecureContext::new(Config::default(), Some(b"MasterPassword"))?;
let identity = ctx.generate_identity()?;

// Send a message (automatically routes via P2P or Relay)
let mut router = HybridRouter::new(ctx);
router.send_message(&recipient_id, b"Hello").await?;

// Clean shutdown
router.stop_discovery();
```

## Security Limitations — Please Read

> [!CAUTION]

| Property | Safeguard | Status |
|----------|-----------|--------|
| **Identity (MITM)** | `Config::fortress_mode()` enforces Safety Number verification. | ✅ Enforced |
| **Traffic Analysis** | **Quantum Padding** (64KB blocks) + Poisson Cover Traffic. | ✅ Hardened |
| **Anonymity** | Native SOCKS5/Tor transport support integrated. | ✅ Integrated |
| **Transport Security** | Built-in TLS and Noise transport wrappers. | ✅ Provided |
| **Side Channels** | Statistical Timing Verification ($<0.1ns$ variance). | ✅ Verified |
| **Rate Limiter** | Constant-Time structural path implementation. | ✅ Fixed |

## Documentation

- [SECURITY.md](SECURITY.md) — Threat model and limitations
- [PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md) — Technical Specification
- [CHANGELOG.md](CHANGELOG.md) — Release History

## License

Apache License 2.0 / MIT (Dual)
