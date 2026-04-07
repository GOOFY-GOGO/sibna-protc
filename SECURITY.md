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
| **Data Confidentiality** | ChaCha20-Poly1305 (256-bit) AEAD | Functional Tests | Logic Implemented |
| **Quantum Resistance** | ML-KEM-768 + X25519 Hybrid | Handshake Logic | Under Evaluation |
| **Handshake Safety** | Lexicographical Role Resolution | Determinism Tests | Logic Implemented |
| **Forward Secrecy** | HMAC-SHA256 ratchet chains | Ratchet Tests | Logic Implemented |
| **Side-Channel Defense** | `subtle` Constant-Time primitives | Statistical Bench | Internal Evaluation Ongoing |
| **Memory Safety** | `Zeroize` on drop / memory pinning | Manual Code Review | Logic Implemented |
| **Traffic Analysis** | Noise-prefix padding (up to 64KB) | Padding Tests | Logic Implemented |
| **Identity Anchoring** | Cryptographic TOFU Pinning | MITM Rejection | Policy Enforced |
| **DoS Protection** | Integrated rate-limiting paths | Benchmark Tests | Logic Implemented |

---

## Non-Guarantees & Known Limitations

Sibna Protocol v3.0.0 is built on best-effort security engineering, but it does **not** provide guarantees against the following:

1.  **Hardware-Level Side Channels**: Resistance is implemented at the software layer. Differential Power Analysis (DPA) or EM side-channels on physical hardware are not mitigated.
2.  **Shared Cloud Environments**: In virtualized or multi-tenant cloud environments (e.g., AWS/GCP), micro-architectural attacks (Spectre/Meltdown style) may still pose a risk to constant-time execution.
3.  **Untrusted OS/Root**: If the underlying Operating System is compromised, the protocol's memory pinning and secure storage can be bypassed by an attacker with root/kernel access.
4.  **Future Quantum Algorithms**: While ML-KEM-768 provides currently accepted post-quantum resistance, it is not a guarantee against future theoretical advancements in quantum cryptanalysis.

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
