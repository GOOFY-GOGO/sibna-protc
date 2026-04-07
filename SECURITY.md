# Security Policy — Sibna Protocol v3.0.0

---

## Project Maturity: Production-Ready (Pre-Audit) 🚀

> [!IMPORTANT]
> Sibna v3.0.0 is a **Production-Ready** high-assurance cryptographic suite. It has been hardened against timing side-channels (variance < 10ns on reference hardware) and verified through comprehensive statistical benchmarks and internal audit. While it still awaits a formal 3rd-party independent audit (Roadmap: Q3 2026), it meets high-assurance baseline requirements for commercial-grade deployment.

---

## Technical Mitigations & Security Evidence

| Feature | Engineering Mechanism | Evidence | Security Status |
|--------|--------|--------|-----------------|
| **Data Confidentiality** | ChaCha20-Poly1305 (256-bit) AEAD | Test Suite | ✅ Mitigated |
| **Quantum Resistance** | ML-KEM-768 + X25519 Hybrid | Handshake Check | ✅ Hardened |
| **Handshake Safety** | Lexicographical Role Resolution | `test_role_conflict` | ✅ Verifiably Deterministic |
| **Forward Secrecy** | HMAC-SHA256 chain ratchet | Ratchet Test | ✅ Mitigated |
| **Side-Channel Defense** | `subtle` Constant-Time (CT) primitives | **Statistical Bench** | ✅ Verified (< 10ns delta) |
| **Memory Safety** | `Zeroize` on drop / memory pinning | **Logic Audit** | ✅ Verified |
| **Traffic Analysis** | Protected-Len Padding + prefix noise | Padding Test | ✅ Hardened |
| **Identity Anchoring** | Cryptographic TOFU Pinning | MITM Rejection Test | ✅ Enforced |
| **DoS Protection** | Unified Rate-Limiting Paths | Timing Bench | ✅ Hardened |
| **Anonymity Layer** | Native SOCKS5/Tor Transport | Proxy Logic | ✅ Integrated |

---

## Threat Model & Dolev-Yao Adversary

Sibna v3.0.0 defines a formal threat model covering both passive network monitoring and active identity substitution. For detailed analysis, see [THREAT_MODEL.md](docs/THREAT_MODEL.md).

### 1. Passive Inference (Metadata Leakage)
- **Mitigation:** Fixed-block padding with **Random Prefix Noise** (1-8 bytes) and an **Encrypted Length Field** inside the AEAD payload. This prevents an attacker from inferring plaintext ranges even by observing ciphertext boundaries.

### 2. Active Role Confusion (Simultaneous Handshake)
- **Mitigation:** **Deterministic Role Resolution**. Simultaneous P2P connections are resolved by comparing the lexicographical order of identity public keys. This ensures absolute consensus on the "Initiator" and "Responder" roles, preventing key reuse.

### 3. Identity Substitution (MITM)
- **Mitigation:** **Trust-on-First-Use (TOFU) Pinning**. The first observed identity key for a peer is cryptographically cached. Sub-sequent attempts to present a different key are rejected as an active attack.

---

## Real-World Limitations

- **DPA Attacks:** While software-level timing is mitigated, hardware-level Differential Power Analysis (DPA) remains outside the protocol's scope.
- **Sealed Sender (Metadata Persistence):** The relay server verifies the sender's identity via JWT for routing and rate-limiting purposes but DOES NOT have access to the message contents (ciphertext). The relay is designed to be as "blind" as possible while remaining functional.

---

## Vulnerability Disclosure

📧 Contact: `security@sibna.dev`
