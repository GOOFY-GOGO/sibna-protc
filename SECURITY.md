# Security Policy — Sibna Protocol v3.0.0

---

## Project Maturity: Hardened Security-Oriented Implementation (Pre-Audit)

> [!IMPORTANT]
> Sibna v3.0.0 is a security-hardened cryptographic suite. It has been engineered to mitigate timing side-channels and validated through statistical benchmarks and internal architectural review. While it awaits a formal 3rd-party independent audit (Roadmap: Q3 2026), it is built to high-assurance baseline requirements for sensitive deployments.

---

## Technical Mitigations & Security Evidence

| Feature | Engineering Mechanism | Evidence | Security Status |
|--------|--------|--------|-----------------|
| **Data Confidentiality** | ChaCha20-Poly1305 (256-bit) AEAD | Functional Tests | ✅ Mitigated |
| **Quantum Resistance** | ML-KEM-768 + X25519 Hybrid | Handshake Logic | ✅ Hardened |
| **Handshake Safety** | Lexicographical Role Resolution | Determinism Tests | ✅ Verified |
| **Forward Secrecy** | HMAC-SHA256 ratchet chains | Ratchet Tests | ✅ Mitigated |
| **Side-Channel Defense** | `subtle` Constant-Time primitives | **Statistical Bench** | ✅ Hardened |
| **Memory Safety** | `Zeroize` on drop / memory pinning | Manual Audit | ✅ Verified |
| **Traffic Analysis** | Noise-prefix padding (up to 64KB) | Padding Tests | ✅ Hardened |
| **Identity Anchoring** | Cryptographic TOFU Pinning | MITM Rejection | ✅ Enforced |
| **DoS Protection** | Integrated rate-limiting paths | Benchmark Tests | ✅ Hardened |

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
📧 `security@sibna.dev`
