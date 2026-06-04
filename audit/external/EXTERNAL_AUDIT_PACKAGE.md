# Sibna Protocol v3.1 — External Audit Package

This document provides a comprehensive guide for third-party cryptographic and security auditors to review the Sibna Protocol implementation.

## 1. Project Overview
Sibna is a high-security, end-to-end encrypted (E2EE) communication protocol implemented in Rust. It implements a hardened version of the Signal Protocol (X3DH + Double Ratchet) with hybrid Post-Quantum Cryptography (ML-KEM-768).

**Primary Goal:** Provide a production-ready, audit-able cryptographic core for secure messaging applications.

## 2. Audit Scope
The audit should focus on the following critical components:

### A. Cryptographic Core (`core/src/crypto/`)
- **AEAD Implementation**: Verification of ChaCha20-Poly1305 usage and nonce management.
- **KDF Chains**: Review of HKDF-SHA256 implementations and domain separation tags.
- **PQC Integration**: Verification of the ML-KEM-768 hybrid path and fips203 implementation.
- **Memory Hygiene**: Review of `Zeroize` and `mlock` usage for sensitive key material.

### B. Handshake & Ratchet (`core/src/handshake/` & `core/src/ratchet/`)
- **X3DH Logic**: Verification of the transcript binding and SPK signature checks.
- **Double Ratchet**: Review of the symmetric and DH ratchet steps, specifically the "Post-Compromise Security" property.
- **Header Encryption**: Audit of the v3.1 header encryption implementation and its resistance to correlation.

### C. P2P & Transport (`core/src/p2p/` & `core/src/transport/`)
- **SOCKS5/Tor Tunneling**: Review of the raw SOCKS5 implementation for potential leaks.
- **mDNS Discovery**: Audit of the identity-hiding mechanism and stealth handshake.
- **Relay Logic**: Verification of the "Sealed Sender" property (server should not see sender identity).

### D. FFI & SDKs (`core/src/ffi/` & `sdks/`)
- **C-API Safety**: Review of `unsafe` blocks in the FFI layer and pointer validation.
- **SDK Correctness**: Verification that SDKs (Python, JS, Go, Java, Dart, Flutter) correctly implement the protocol without introducing vulnerabilities.

## 3. Threat Model
The protocol is designed against a **Dolev-Yao Adversary** who can:
- Intercept, modify, and inject any network traffic.
- Compromise the relay server (which should not lead to content decryption).
- Compromise a device's long-term keys (handled via Forward Secrecy).
- Perform traffic analysis (mitigated via Poisson Cover Traffic and Padding).

## 4. Critical Remediation History
Auditors should verify that the following previously identified critical issues remain fixed:
- **SIBNA-2026-001**: Empty plaintext rejection in padding (Fixed).
- **SIBNA-2026-003**: Weak password KDF in non-argon2 builds (Fixed).
- **SIBNA-2026-004**: Bincode serialization mismatch (Fixed).
- **SIBNA-2026-031**: C++ SDK NULL pointer dereferences (Fixed).

## 5. Verification Suite
The following tests should be run to verify the current state:
- `cargo test --workspace` (Unit + Integration tests)
- `cargo test --test attack_tests` (12-vector security audit suite)
- `cargo test --test offensive_test` (Adversarial testing)
- `cargo clippy --all-targets --all-features` (Linting)

## 6. Contact & Coordination
Technical lead: Sibna Security Team.
All findings should be reported via the internal issue tracker or the designated security contact.
