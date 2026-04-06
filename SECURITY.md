# Security Model & Threat Architecture — Sibna Protocol v3.0.0

---

## Project Maturity

> [!WARNING]
> Sibna v3.0.0 is an independent cryptographic implementation leveraging audited primitives from RustCrypto. **No independent external security audit has been performed** on the protocol orchestration or state machines. We strongly advise commissioning an independent cryptographic audit before integrating this codebase into mission-critical environments.

---

## Implemented Protections

| Feature | Mechanism | Status |
|--------|--------|--------|
| **Data Confidentiality** | ChaCha20-Poly1305 (256-bit) AEAD | ✅ |
| **Quantum Resistance** | ML-KEM-768 + X25519 Hybrid | ✅ Default |
| **Key-Substitution / UKS** | BLAKE3 Transcript Binding in X3DH v10 | ✅ |
| **P2P Anonymity** | Stealth Handshake — `StealthBundle` encrypted | ✅ |
| **Forward Secrecy** | HMAC-SHA256 chain ratchet per message | ✅ |
| **Post-Compromise Security** | DH ratchet after every full round-trip | ✅ |
| **Storage Protection** | Argon2id (memory-hard) when `feature="argon2"` | ✅ |
| **Swap Memory Protection**| `mlock` (Unix) / `VirtualLock` (Windows) | ✅ |
| **Device Key Pinning** | `device_id [u8;16]` mixed into KDF | ✅ |
| **Sealed Sender** | Server cannot read sender identity | ✅ |
| **Envelope Integrity** | Ed25519 + SHA-512 (includes `is_dummy`) | ✅ |
| **Message Padding** | Fixed block padding (256B/1KB/4KB/16KB) | ✅ |
| **Cover Traffic** | Exponential Distribution (Poisson) — ~5s mean | ✅ |
| **P2P Peer Limits** | `MAX_ACTIVE_PEERS = 500` memory boundary | ✅ |
| **Strict Verification** | `Config::core_mode()` Enforces Safety Numbers | ✅ |

---

## Threat Model (Attacker Capabilities)

Sibna is designed around a strict Threat Model. It is critical to understand what adversaries can and cannot do.

### 1. Global Passive Adversary (GPA)
**Definition:** An entity (e.g., an ISP or state actor) capable of monitoring, recording, and analyzing all packets flowing across the entire internet.
- **What they CAN do:** Analyze traffic frequencies. They can see when connections are made, IP addresses, and encrypted packet sizes.
- **What we mitigate:** `Cover Traffic` and `Message Padding` drastically increase the noise-to-signal ratio, rendering frequency analysis mathematically challenging.
- **What we CANNOT prevent:** Without `proxy_url` (Tor/SOCKS5), the GPA ultimately knows that Node A is communicating with Node B. Absolute anonymity requires routing the protocol via Tor.

### 2. Active Network Attacker (Man-In-The-Middle)
**Definition:** An entity capable of intercepting, modifying, dropping, or injecting packets between peers or between a peer and the central relay server.
- **What they CAN do:** Attempt to block messages or serve forged Public Keys to Alice masquerading as Bob.
- **What we mitigate:** The protocol inherently rejects unsigned/tampered packets via AEAD. To defeat Key-Injection, `Config::require_safety_numbers = true` forcefully mandates out-of-band verification via QR codes, physically neutralizing the MITM topology.
- **What we CANNOT prevent:** If a developer ignores Safety Numbers and relies exclusively on Trust-On-First-Use (TOFU), the very first communication channel is susceptible to MITM interception.

### 3. Local Hardware Attacker
**Definition:** An entity with physical or remote access to the device executing the protocol.
- **What they CAN do:** Attempt to extract forensic key material from RAM or disk.
- **What we mitigate:** Secrets are encrypted on disk via Argon2id (defeating weak passwords). Live RAM is pinned (`mlock`) to prevent paging to swap files, and keys are zeroized instantly upon drop (`Zeroize` crate).
- **What we CANNOT prevent:** A rooted device (e.g. executing kernel-level malware like Pegasus) can hook directly into memory before zeroization or extract the raw inputs. Sibna provides no guarantees against a compromised host OS.

---

## Known Restraints

- **Anonymity:** Not a built-in feature. IPs are visible to the server natively. True anonymity requires configuring proxy routing manually within `P2pConfig`.
- **Timing Oracle (Rate Limiter):** A minor, measurable sub-millisecond discrepancy exists in `RateLimiter::check()` due to global `RwLock` structures. Highly sophisticated local observers might deduce client_id presences. Fix deferred.
- **Side Channels:** `subtle` protects against timing attacks exclusively inside the codebase logic. Hardware side-channels (Spectre/Meltdown) are outside this protocol's threat remediation scope.

---

## Cryptographic Parameters

| Parameter | Algorithm |
|---------|-----------|
| KEM (Quantum) | ML-KEM-768 (FIPS 203) — Category 3 |
| DH (Classical) | X25519 — ~128-bit equivalent |
| AEAD | ChaCha20-Poly1305 — 256-bit |
| KDF | HKDF-SHA256 |
| Transcript Hash | BLAKE3 |
| Signature | Ed25519 |
| Password KDF | Argon2id |
| HMAC (Challenges) | HMAC-SHA256 |
| Constant Time | `subtle` crate |

---

## Vulnerability Reporting

**DO NOT open public issues for security vulnerabilities.**  
📧 Contact: `security@sibna.dev`
