# Changelog — Sibna Protocol

All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [3.0.1] — 2026-06-04 (Security Hardening)

### Fixed
- **C++ SDK double-free**: `create_session` and `create_group` returned `unique_ptr` with default deleter on pointers still owned by internal maps. Now uses null deleter for non-owning pointers.
- **C++ SDK BIO_new NULL checks**: `Utils::bytes_to_base64` and `Utils::base64_to_bytes` now validate `BIO_new()` return values before use.
- **Cover traffic delivery**: `send_dummy_to_relay` now actually transmits encrypted dummy packets via the relay server instead of silently discarding them.
- **Relay message delivery**: `send_via_relay` now constructs and sends signed envelopes via `RelayClient` instead of only encrypting without transmission.
- **Tor/SOCKS5 proxy wiring**: `P2pNode::connect` now routes through `connect_with_optional_proxy` using the configured proxy address. `HybridRouter` initializes `RelayClient` with proxy support from `Config::proxy_url`.
- **Documentation inconsistencies**: Updated sled references across 8 documentation files to reflect the completed migration to redb.

### Changed
- **RelayClient**: Added `send_envelope` method for transmitting signed JSON envelopes to the relay server.
- **HybridRouter**: Added `relay_client` field and `init_relay_from_config` method for relay integration.
- **Dead code removal**: Removed unused `Socks5Config` and `TlsConfig` structs from `transport/mod.rs`.

### Added
- **C++ SDK test suite**: 7 test files covering identity, crypto, session, context, group, safety number, and utility operations (37 test cases total).
- **Test infrastructure**: CMakeLists.txt for C++ tests with Catch2 framework integration.

---

## [3.0.0] — 2026-04-06 (Ultimate Upgrade)

### Security Fixes — CRITICAL
- **Timing Oracle Fix**: Replaced string comparisons with `subtle::ConstantTimeEq` for challenge authentication.
- **Transcript Binding**: Included `device_id_A` and `device_id_B` in the X3DH transcript hash for absolute session binding.
- **KDF Hardening**: Corrected HKDF salt usage (salt=T) and updated ratchet labels to `v3.0.0`.
- **Padding Unification**: Unified all padding implementations to use the hardened "Noise Prefix" format.
- **Documentation Overhaul**: Removed all unverified security claims (Kani, Fuzzing) to ensure technical honesty ("مامن قول و فعل").

### Major Features
- **Delivery ACKs (Zero Message Loss)**: Server-side queueing algorithm with Store-and-Forward policy.
- **Last Resort PreKey**: Prevents One-Time key starvation for offline nodes.
- **WebRTC Fast-path**: Engineered signaling wrappers for audio/video calls.
- **Hybrid Router**: Seamless fallback between P2P discovery and relay routing.

### Maintenance
- Deleted leaked PowerShell output (`check_out.txt`).
- Standardized project version to `v3.0.1` across all crates and documentation.

---

## [0.9.0] — 2024-03-20
- Post-Quantum integration (ML-KEM-768).
- Finalized foundational P2P mDNS Discovery routing paths.

## [0.8.0] — 2024-01-15
- Implementation of the foundational cryptographic Double Ratchet.
- Implementation of Classic X3DH key negotiation.
