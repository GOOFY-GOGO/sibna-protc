# Sibna Protocol Specification — v3.0.0 

---

## 1. Definitions & Terminology

The following keywords are used in this specification to define protocol behavior:
- **MUST**: Indicates a mandatory requirement for security or interoperability.
- **SHOULD**: Indicates a recommended but non-mandatory behavior.
- **MAY**: Indicates an optional feature.
- **Protocol Invariant**: A security property that must hold true across all valid states and transitions of the protocol world-view.

## 2. Key Agreement: X3DH v3

### 1.1 Key Types

| Type | Algorithm | Lifespan |
|-------|------------|-------|
| Identity Key (IK) | Ed25519 / X25519 | Permanent |
| Signed Prekey (SPK) | X25519 signed by IK | Medium |
| One-Time Prekey (OPK) | X25519 | Single Use |
| Ephemeral Key (EK) | X25519 | Single Session |
| ML-KEM-768 Key | ML-KEM-768 (FIPS 203) | Tied to SPK |

### 1.2 Handshake Steps

```
Alice (Initiator)                           Bob (Responder)
─────────────────────────────────────────────────────────
1. Fetches prekey bundle from server
2. Generates random EK
3. Encapsulates KEM secret: (ss_kem, ct_kem) = KEM.Enc(SPK_B.pk) [if PQC]
4. Computes classical DH:
   dh1 = DH(IK_A, SPK_B)
   dh2 = DH(EK_A, IK_B)
   dh3 = DH(EK_A, SPK_B)
   dh4 = DH(EK_A, OPK_B)  [if OPK exists]
5. Computes Transcript Hash:
   T = BLAKE3(IK_A || IK_B || EK_A || SPK_B || OPK_B || device_id_A || device_id_B)
6. Derives final key:
   SK = HKDF-SHA256(salt=T, ikm=ss_kem || dh1 || dh2 || dh3 || dh4)
```

**Transcript Binding:** Binding the derived key to all participating public keys and device IDs prevents key-substitution and UKS (Unknown Key-Share) attacks.

**Quantum Hybrid:** An attacker must break **both** (X25519 and ML-KEM-768) simultaneously to compromise the handshake.

---

## 2. Session Management: Double Ratchet

### 2.1 Symmetric Ratchet

```
chain_key[n+1] = HMAC-SHA256(chain_key[n], 0x02)
message_key[n] = HMAC-SHA256(chain_key[n], 0x01)
```

After use, the `message_key` is immediately zeroized (Forward Secrecy).

### 2.2 DH Ratchet

After each full round trip, a new X25519 exchange occurs — resetting the `root_key` (Post-Compromise Security).

---

## 3. Hybrid Routing (P2P + Relay)

### 3.1 "P2P-First" Policy

Sibna attempts a P2P handshake via mDNS/Stealth discovery before falling back to the authenticated relay server.

### 3.2 Security Limits

| Limit | Value | Purpose |
|------|--------|-------|
| `MAX_ACTIVE_PEERS` | 500 | Prevent mDNS flood |
| `MAX_MESSAGE_BYTES` | 64 MiB | Prevent massive memory allocations |
| Address Validation | Rejects loopback / multicast / unspecified / port 0 | Prevent local pivot attacks |

---

## 4. Metadata Protection

### 4.1 Sealed Sender
The relay server identifies the sender for routing but cannot decrypt message contents.

### 4.2 Message Size Padding
Messages use a hardened padding format with a noise prefix to prevent size inference.

**Format:** `[8 bytes Noise] [2 bytes LE Payload length] [Payload] [Random Padding]`
Standard block size is 1KB; Hardened mode uses 64KB.

---

## 5. Server Authentication

1. Client requests 32-byte challenge.
2. Server stores challenge with HMAC integrity and TTL.
3. Client signs challenge with Ed25519.
4. Server verifies HMAC (Constant-Time) and signature, then issues JWT.

---

---

## 7. Formal Security Assumptions

Sibna Protocol v3.0.0 is designed under the following cryptographic hardness assumptions. If any of these are broken, the security invariants of the protocol may fail.

| Component | Formal Assumption | Description |
|-----------|-------------------|-------------|
| **X25519 DH** | CDH (Computational Diffie-Hellman) | It is computationally infeasible to compute `g^(ab)` from `g^a` and `g^b`. |
| **ML-KEM-768** | Module-LWE (Learning With Errors) | The underlying lattice problem is computationally hard even for quantum computers. |
| **HKDF-SHA256** | PRF (Pseudo-Random Function) | HKDF behaves like a secure pseudo-random function extractor/expander. |
| **Authentication** | EUF-CMA (Existential Unforgeability) | Ed25519 signatures cannot be forged under chosen message attacks. |
| **Encryption** | IND-CCA2 | The AEAD scheme (ChaCha20-Poly1305) provides ciphertext indistinguishability under chosen-ciphertext attacks. |

---

## 8. Comparative Analysis

Sibna v3.0.0 is a hybrid design influenced by the Signal and Noise protocols, with specialized hardening for P2P and quantum resilience.

| Feature | Signal Protocol | Noise Protocol | Sibna v3.0.0 |
|---------|-----------------|----------------|--------------|
| **Core Handshake** | X3DH | Customizable Patterns | **X3DH v3** |
| **Quantum Safe** | Optional (PQX3DH) | No (Standard) | **Hybrid (Default)** |
| **Role Resolution** | Server-mediated | Pattern-driven | **Lexicographical** |
| **Transcript Binding** | Partial | Pattern-bound | **Full (Hardened)** |
| **Metadata Protection** | Sealed Sender (V2) | N/A | **Sealed Sender (Blinded)** |
| **Padding** | Implicit | N/A | **Hardened (64KB Noise)** |
| **Forward Secrecy** | Double Ratchet | Optional (Rekey) | **Double Ratchet** |

---

## 10. Handshake Message Formats (Formal Specification)

Handshake messages MUST follow the following binary structure. Fields are in Little-Endian (LE) format where applicable.

### 10.1 `HandshakeInitiate` (Alice -> Bob)
```rust
struct HandshakeInitiate {
    version: u8,               // Protocol context (MUST be 3)
    ephemeral_pk: [u8; 32],    // EK_A (X25519)
    identity_pk: [u8; 32],     // IK_A (Ed25519)
    kem_ciphertext: [u8; 1088], // ML-KEM-768 ciphertext (ss_kem)
    transcript_hash: [u8; 32], // Hash of IDs and Keys (BLAKE3)
    signature: [u8; 64],       // Ed25519 signature of the hash
    device_id: [u8; 16],       // Initiator device identifier
}
```

### 10.2 `HandshakeResponse` (Bob -> Alice)
```rust
struct HandshakeResponse {
    version: u8,               // Protocol context (MUST be 3)
    ephemeral_pk: [u8; 32],    // EK_B (X25519)
    acknowledgment: [u8; 32],  // BLAKE3 hash of received initiate
}
```

---

## 11. Security Goals & Protocol Invariants

The Sibna Protocol is designed to ensure the following fundamental invariants. A violation of any invariant constitutes a protocol-level security breakage.

| Invariant | Goal | Description |
|-----------|------|-------------|
| **Key Indistinguishability** | Confidentiality | The derived session key `SK` MUST be indistinguishable from random to an adversary $\mathcal{A}$ under the CDH + LWE hardness assumptions. |
| **Transcript Constancy** | Integrity | The handshake MUST fail if any participating public key or device identifier is modified during transport (enforced by BLAKE3 transcript binding). |
| **Session Isolation** | Forward Secrecy | A compromise of current `message_key[n]` MUST NOT compromise `message_key[n-1]` (enforced by immediate zeroization of keys). |
| **Healing Consistency** | PCS | After a successful DH ratchet round-trip, the `root_key` MUST be refreshed, healing the session from previous leakage. |
| **Identity Uniqueness** | Authenticity | A single session MUST NOT be established between different identity pairs (enforced by IK_A \|\| IK_B binding in the transcript). |

---

## 12. Deniability & Privacy Goals

| Property | Level | Engineering Evidence |
|----------|-------|----------------------|
| **Perfect Forward Secrecy** | Full | HMAC-SHA256 ratchet chains + DH Ephemeral update. |
| **Post-Compromise Security** | Full | Independent DH Ratchet round-trips. |
| **Identity Hiding** | Partial | Handshake uses Ed25519 over transcript hash; identity keys are known to the relay but payload is sealed. |
| **Traffic Anonymity** | Integrated | Native support for SOCKS5/Tor to decouple IP identity. |
