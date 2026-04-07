# Security Policy — Sibna Protocol v3.0.0

> [!CAUTION]
> **Security Disclaimer**: Sibna is an experimental cryptographic implementation. It has not undergone formal 3rd-party review. Cryptographic software should not be deployed in critical production environments without independent validation.

---

## Project Maturity: Security-Hardened Research Prototype (Pre-Audit)

> [!IMPORTANT]
> Sibna v3.0.0 is an architectural implementation designed with high-assurance security invariants. It has been engineered to mitigate common side-channel vulnerabilities and evaluated through internal statistical benchmarks. A formal independent audit is pending (Roadmap: Q3 2026).

---

| Feature | Engineering Mechanism | Evaluation Evidence | Security Status |
|--------|--------|--------|-----------------|
| **Data Confidentiality** | ChaCha20-Poly1305 (256-bit) AEAD | Functional Tests | ✅ Mitigated |
| **Quantum Resistance** | ML-KEM-768 + X25519 Hybrid | Handshake Logic | ✅ Designed for Resilience |
| **Handshake Safety** | Lexicographical Role Resolution | Determinism Tests | ✅ System Evaluated |
| **Forward Secrecy** | HMAC-SHA256 ratchet chains | Ratchet Tests | ✅ Mitigated |
| **Side-Channel Defense** | `subtle` Constant-Time primitives | **Statistical Bench** | ✅ Evaluation Ongoing |
| **Memory Safety** | `Zeroize` on drop / memory pinning | Manual Code Review | ✅ Logic Implemented |
| **Traffic Analysis** | Noise-prefix padding (up to 64KB) | Padding Tests | ✅ Designed for Resistance |
| **Identity Anchoring** | Cryptographic TOFU Pinning | MITM Rejection | ✅ Policy Enforced |
| **DoS Protection** | Integrated rate-limiting paths | Benchmark Tests | ✅ Designed for Resistance |

---

## Threat Model & Dolev-Yao Adversary

Sibna v3.0.0 defines a formal threat model covering both passive network monitoring and active identity substitution.

### 1. Passive Inference (Traffic Analysis)
- **Mitigation:** Fixed-block padding with **Random Noise Prefixes** and an **Encrypted Length Field** inside the AEAD payload. This prevents an observer from inferring plaintext length or content type by inspecting ciphertext boundaries.

### 2. Active Role Confusion (Simultaneous Handshake)
- **Mitigation:** **Deterministic Role Resolution**. Simultaneous P2P connections are resolved by comparing the lexicographical order of identity public keys. This ensures absolute consensus on the "Initiator" and "Responder" roles, preventing session key reuse.

### 3. Identity Substitution (MITM)
- **Mitigation:** **Trust-on-First-Use (TOFU) Pinning**. The first observed identity key for a peer is cryptographically cached. Subsequent attempts to present a different key for the same identifier are rejected as an active attack.

---

## Real-World Limitations

- **DPA Protection:** While software-level timing is mitigated using constant-time primitives, hardware-level Differential Power Analysis (DPA) remains outside the protocol's current scope.
- **Relay Metadata (Sealed Sender):** The relay server identifies the sender via JWT for routing and rate-limiting purposes but DOES NOT have access to the message contents. The design minimizes the metadata footprint on the infrastructure while maintaining operational stability.

---

## Vulnerability Disclosure

**Do not open public issues for security vulnerabilities.**  
Please report security concerns privately to:  
📧 `sibnaa@zohomail.com`
