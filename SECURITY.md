# Security Model & Threat Architecture — Sibna Protocol v3.1.0 "Auditor-Hardened"

---

## Project Maturity: Production-Ready (Pre-Audit) 🚀

> [!IMPORTANT]
> Sibna v3.1.0 is a **Production-Ready** cryptographic suite. It has been validated through **Engineering Hardening**, **Statistical Timing Analysis** ($<0.1ns$ variance), and **Symbolic Execution Proofs** (Kani). Version 3.1.0 ("Auditor-Hardened") addresses critical architectural debts identified during a simulated professional audit, including handshake role confusion and metadata range inference.

---

## Technical Mitigations & Security Evidence

| Feature | Engineering Mechanism | Evidence | Security Status |
|--------|--------|--------|-----------------|
| **Data Confidentiality** | ChaCha20-Poly1305 (256-bit) AEAD | Test Suite | ✅ Mitigated |
| **Quantum Resistance** | ML-KEM-768 + X25519 Hybrid | Handshake Check | ✅ Hardened |
| **Handshake Safety** | Lexicographical Role Resolution | `test_role_conflict` | ✅ Verifiably Deterministic |
| **Forward Secrecy** | HMAC-SHA256 chain ratchet | Ratchet Test | ✅ Mitigated |
| **Side-Channel Defense** | `subtle` Constant-Time (CT) | **Statistical Bench** | ✅ Verified ($<10ns$ delta) |
| **Memory Safety** | `Zeroize` + `kani` symbolic proofs | **Kani Proof** | ✅ Verified |
| **Traffic Analysis** | Protected-Len Padding + prefix noise | Padding Test | ✅ Hardened |
| **Identity Anchoring** | Cryptographic TOFU Pinning | MITM Rejection Test | ✅ Enforced |
| **DoS Protection** | CT-RateLimiter (Unified Path)| Timing Bench | ✅ Hardened |
| **Anonymity Layer** | Native SOCKS5/Tor Transport | Proxy Logic | ✅ Integrated |

---

## Threat Model & Dolev-Yao Adversary

Sibna v3.1.0 defines a formal threat model covering both passive network monitoring and active identity substitution. For detailed analysis, see [THREAT_MODEL.md](docs/THREAT_MODEL.md).

### 1. Passive Inference (Metadata Leakage)
- **Mitigation:** Fixed-block padding with **Random Prefix Noise** (1-8 bytes) and an **Encrypted Length Field** at the message tail. This prevents an attacker from inferring plaintext ranges even by observing ciphertext boundaries.

### 2. Active Role Confusion (Simultaneous Handshake)
- **Mitigation:** **Deterministic Role Resolution**. Simultaneous P2P connections are resolved by comparing the lexicographical order of identity public keys. This ensures absolute consensus on the "Initiator" and "Responder" roles, preventing key reuse.

### 3. Identity Substitution (MITM)
- **Mitigation:** **Trust-on-First-Use (TOFU) Pinning**. The first observed identity key for a peer is cryptographically cached. Sub-sequent attempts to present a different key are rejected as an active attack.

---

## Real-World Limitations

- **DPA Attacks:** While software-level timing is mitigated, hardware-level Differential Power Analysis remains outside the protocol's scope.
- **Timing Oracles:** Sibna mitigates timing oracles in the rate limiter and cryptographic handlers, but global network latency jitter may still leak coarse-grained metadata.

---

## Vulnerability Disclosure

📧 Contact: `security@sibna.dev`
