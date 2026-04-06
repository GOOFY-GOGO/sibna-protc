# Changelog — Sibna Protocol

All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [3.0.0] — 2026-04-06 (Ultimate Upgrade)

### The 4 Major Architectural Pillars
- **Delivery ACKs (Zero Message Loss)**: Server-side queueing algorithm to retain messages until an explicit `{"type": "ack"}` is received.
- **Last Resort PreKey**: `is_last_resort` key to definitively prevent Offline Node Starvation.
- **WebRTC Fast-path**: Engineered `WsMessage` and `WebRtcSignal` wrappers for pristine audio/video call signaling support.
- **Underlying WebSocket Evolution**: Shift to explicit Tagged Unions for guaranteed data-integrity over active pipes.

### Deep Cryptographic & P2P Upgrades

- **Transcript Binding (v10)**: BLAKE3 transcript hash computed over the entire public key sequence during X3DH — effectively mitigating key-substitution and UKS attacks. Located in `p2p/handshake.rs` & `crypto/kdf.rs`.
- **Stealth Handshake**: Identity bundle (`StealthBundle`) is aggressively encrypted during the initial P2P handshake — preventing a passive listener from determining your identity. Located in `p2p/handshake.rs`.
- **Argon2id KDF**: Replaced repetitive HKDF with Argon2id (memory-hard process) to derive the core storage key from the user-password. Conditional on `feature = "argon2"`. Located in `lib.rs:250`.
- **Memory Pinning**: Pinned the entropy pool to non-swappable physical memory via `mlock` (Unix) and `VirtualLock` (Windows). Located in `crypto/random.rs:46`.
- **Multi-Device device_id**: Intertwined `device_id [u8; 16]` into the Session KDF — enforcing strictly isolated ratchet chains per device. Located in `lib.rs:144`.

### Security Fixes — CRITICAL

- **F-01** `manager.rs`: Mitigated Race Condition inside the P2P discovery loop — Replaced `contains_key + connect + insert` paradigm with `entry().or_insert_with()`.
- **F-02** `manager.rs`: Removed aggressive `unwrap_or_default()` on hex decodes — now safely rejects and logs errors instead of instantiating ghost peers with empty keyframes.

### Security Fixes — HIGH

- **F-03** `manager.rs`: Implemented `MAX_ACTIVE_PEERS = 500` constraint — blocking memory exhaustion vectors triggered via mDNS flood attacks.
- **F-04** `manager.rs`, `relay.rs`: Scrubbed all implementations of `InternalErrorDetailed { details: e.to_string() }` — Debug details are strictly restricted to internal `warn!`/`debug!` logs.
- **F-05** `manager.rs`: Migrated to an `Arc<tokio::sync::Notify>` combined with `stop_discovery()` and `tokio::select!` — enabling surgical interruption of the discovery loop.

### Security Fixes — MEDIUM

- **F-06** `manager.rs`: Infused `MAX_MESSAGE_BYTES = 64 MiB` boundary checks directly preceding memory allocations.
- **F-07** `manager.rs`: Adjusted `is_valid_peer_addr()` logic to preemptively reject loopback / multicast / unspecified / port 0 paths.
- **F-08** `manager.rs`: Shifted cover traffic algorithms to employ an exponential inverse-CDF `(-ln(U) * mean)` mapping as opposed to uniform distribution.
- **N-01** `ws.rs`: Deprecated `to_vec().unwrap_or_default()` substituting explicit `match` boundaries across multiple endpoints.
- **N-02** `rate_limit.rs`: Acknowledged timing oracle behaviors (Partial documentation introduced) — absolute structural remediation delayed for a future minor cycle.
- **N-03** `auth.rs`: Fortified cryptographic challenges to be preserved entirely as `HMAC-SHA256(challenge, jwt_secret)` instances over plaintext constants.
- **N-03b** `auth.rs` (server/src): Mandated `subtle::ConstantTimeEq` utilization during HMAC comparisons opposed to string `!=` operations — securing against timing oracles in the challenge integrity phase.

### Dependency additions

- `server/Cargo.toml`: `hmac = { workspace = true }`, `subtle = { workspace = true }`

### Maintenance operations

- Deleted `core/src/manager_fixed.rs` — Orphan file containing rogue `expect()` instances inside production blocks which was uncompilable in earlier revisions.

---

## [0.9.0] — 2026-03-20

- Post-Quantum integration (ML-KEM-768).
- Finalized foundational P2P mDNS Discovery routing paths.

## [0.8.0] — 2024-XX-XX

- Implementation of the foundational cryptographic Double Ratchet.
- Implementation of Classic X3DH key negotiation.
