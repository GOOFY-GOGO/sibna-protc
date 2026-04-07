# Sibna Protocol Specification — v3.0.0

---

## 1. Key Agreement: X3DH v3

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

## 9. Adversarial Model (Formal)

We define a **Dolev-Yao** style adversary with the following capabilities:
1.  **Network Control**: Full control over all relayed and P2P traffic (Read, Delete, Inject).
2.  **Ephemerality**: Access to session-specific ephemeral keys does not compromise past or future sessions (forward secrecy).
3.  **Limitations**: The adversary is computationally bounded and cannot solve the CDH or Module-LWE problems within the security parameter $2^{128}$.
