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
Standard block size is 1KB; Quantum mode uses 64KB.

---

## 5. Server Authentication

1. Client requests 32-byte challenge.
2. Server stores challenge with HMAC integrity and TTL.
3. Client signs challenge with Ed25519.
4. Server verifies HMAC (Constant-Time) and signature, then issues JWT.

---

## 6. Cryptographic Parameters

| Parameter | Algorithm |
|---------|-----------|
| KDF | HKDF-SHA256 |
| AEAD | ChaCha20-Poly1305 |
| Key Exchange | X25519 + ML-KEM-768 |
| Transcript Hash | BLAKE3 |
| Signature | Ed25519 |
| Argon2 | Argon2id (m=64MB, requires `feature = "argon2"`) |
| CT Compare | `subtle::ConstantTimeEq` |
