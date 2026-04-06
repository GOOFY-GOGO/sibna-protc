# Sibna Protocol: Formal Threat Model (v3.1.0)

## 1. Adversary Model: Dolev-Yao Extended
Sibna assumes an adversary with full control over the network medium (read, write, delete, delay, and reorder packets). We extend this model with **Global Passive Adversary (GPA)** capabilities for traffic analysis research.

### 1.1 Network Adversary Capabilities
- **Passive:** Eavesdrop on all P2P and Relay traffic. Capture historical ciphertexts for future decryption (mitigated by Forward Secrecy).
- **Active:** Initiate handshakes, replay old messages (mitigated by ratchet sequence numbers), and attempt to substitute identity keys (mitigated by TOFU Pinning).
- **Analysis:** Infer packet contents via size/timing (mitigated by Protected-Len Padding and Prefix Noise).

---

## 2. Security Invariants

### 2.1 Confidentiality & Integrity
- **Mechanism:** ChaCha20-Poly1305 AEAD.
- **Invariant:** An attacker cannot read or modify payloads without the session-specific root key.
- **Bound:** $2^{256}$ security level (Pre-Quantum).

### 2.2 Quantum Resistance
- **Mechanism:** ML-KEM-768 + X25519 Hybrid.
- **Invariant:** Even a Cryptographically Relevant Quantum Computer (CRQC) cannot recover the shared secret from a recorded handshake.
- **Bound:** NIST Level 3 (Quantum) + 128-bit (Classical).

### 2.3 Forward Secrecy (FS)
- **Mechanism:** HMAC-SHA256 Double Ratchet.
- **Invariant:** Compromise of the *current* session keys does not reveal *past* messages. New DH keys are generated for every message/turn.

### 2.4 Post-Quantum Compromise Resiliency (PCS)
- **Mechanism:** Continuous DH Ratcheting.
- **Invariant:** If a state is compromised, the protocol self-heals as soon as another successful DH exchange occurs.

---

## 3. Specific Mitigations (v3.1.0 Hardening)

### 3.1 Metadata Range Inference
**Threat:** Observing the 2-byte length field in a padded block allows an attacker to estimate the plaintext size range ($BlockSize - PadLen$).
**Mitigation:** 
1. **Random Prefix Noise:** 1-8 random bytes at the start of every encrypted block.
2. **Trailing Length:** The `pad_len` field is moved to the end of the AEAD-protected payload.
3. **Entropy:** The entire block is encrypted, making the "noise" and "padding" indistinguishable from the "payload" to an observer.

### 3.2 Handshake Role Collision
**Threat:** Two peers initiating a connection simultaneously using the same identity keys may reach different conclusions about who is the "Initiator", leading to session desync or key reuse.
**Mitigation:** **Lexicographical Public Key Comparison**. The peer with the numerically smaller `id_pub_key` always assumes the **Responder** role. This is a purely mathematical consensus requiring no negotiation.

### 3.3 Identity Pinning (TOFU)
**Threat:** A network attacker presents a malicious identity key during the first handshake (MITM).
**Mitigation:** **Trust-On-First-Use**. Sibna "pins" the first successfully exchanged identity key. If the long-term key changes, the protocol fails the handshake and alerts the user to a potential MITM attack.

---

## 4. Out-of-Scope Threats
- **Endpoint Compromise:** If the OS kernel or filesystem is fully compromised, secrets residing in RAM (before zeroization) or persistent storage are at risk.
- **Side-Channel (Physical):** Power analysis or EM emanations from mobile devices are not mitigated by the software protocol.
- **Network Metadata (Coarse):** While Sibna hides message sizes and specific timings, it does not hide the IP endpoints unless used over Tor/SOCKS5.
