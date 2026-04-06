# Sibna Protocol Specification — v3.0.0

---

## 1. Key Agreement: X3DH v10

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
3. Encapsulates KEM secret: (ss_kem, ct_kem) = KEM.Enc(SPK_B.pk)
4. Computes classical DH:
   dh1 = DH(IK_A, SPK_B)
   dh2 = DH(EK_A, IK_B)
   dh3 = DH(EK_A, SPK_B)
   dh4 = DH(EK_A, OPK_B)  [if OPK exists]
5. Computes Transcript Hash:
   T = BLAKE3(IK_A || IK_B || EK_A || SPK_B || OPK_B || device_id_A || device_id_B)
6. Derives final key:
   SK = HKDF-SHA256(salt=T, ikm=ss_kem || dh1 || dh2 || dh3 || dh4, info="SibnaPQX3DH_v10")
```

**Transcript Binding:** Binding the derived key to all participating public keys prevents key-substitution and UKS (Unknown Key-Share) attacks.

**Quantum Hybrid:** An attacker must break **both** (X25519 and ML-KEM-768) simultaneously to compromise the handshake.

> ⚠️ Without `feature = "pqc"`: Only X25519 is used, leaving it vulnerable to Shor's algorithm.

### 1.3 Stealth Handshake (Identity Hiding in P2P)

In direct P2P handshakes, the initiator's identity bundle (`StealthBundle`) is encrypted inside a `StealthEnvelope` derived from the initial exchange. A passive network observer cannot determine the initiator's identity.

```
StealthBundle { bundle_bytes, device_id } → AES-GCM → StealthEnvelope
```

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

```
send_message(recipient, plaintext)
├── [plaintext > 64 MiB] → Immediate Rejection
├── [Active P2P Session] → peer.send_message()
│       ├── Success → return Ok
│       └── Failure → warn + fallback
└── send_via_relay() → encrypt → Ok
```

### 3.2 Security Limits

| Limit | Value | Purpose |
|------|--------|-------|
| `MAX_ACTIVE_PEERS` | 500 | Prevent mDNS flood |
| `MAX_MESSAGE_BYTES` | 64 MiB | Prevent massive memory allocations |
| Address Validation | Rejects loopback / multicast / unspecified / port 0 | |
| Cover Traffic | Exponential distribution `(-ln(U) × 5s)` clamped to [min, max] | Obfuscate activity patterns |

### 3.3 P2P Discovery (mDNS)

- Background loop utilizing `tokio::select!` on a cancellation token.
- `stop_discovery()` enables clean shutdown.
- Rejects invalid `peer_id` (failed or empty hex decode).
- Peer limit is enforced prior to any connection attempt.
- TOCTOU-safe via `DashMap::entry().or_insert_with()`.

---

## 4. Sealed Sender

The server routes envelopes without knowing the sender. Each `SignedEnvelope` is cryptographically signed using Ed25519 over the following payload:

```
SHA-512(recipient_id ∥ payload_hex ∥ timestamp_le ∥ message_id ∥ is_dummy)
```

`is_dummy` is bound within the signature — this prevents the server from intentionally reclassifying genuine messages as dummy traffic or vice versa.

---

## 5. Message Size Padding

| Mode | Block Size | Use Case |
|-------|------------|-----------|
| `None` | No padding | Not recommended |
| `Small` | 256 B | IoT / Lightweight |
| `Standard` (Default) | 1 KB | General Messaging |
| `Large` | 4 KB | File Transfers |
| `Maximum` | 16 KB | Maximum Protection |
| `Custom(n)` | n bytes | Advanced use cases |

**Format:** `[ plaintext | random_padding | 2-byte LE padding_len ]`

---

## 6. Server Authentication

```
1. Client requests challenge (32 random bytes)
2. Server stores in sled:
   format!("{}:{}:{}", challenge_hex, HMAC-SHA256(challenge_hex, jwt_secret), expires_at)
3. Client signs challenge with Ed25519
4. Server verifies:
   a. HMAC integrity via subtle::ConstantTimeEq (Constant Time)
   b. Expiration date
   c. Ed25519 signature
5. Issues valid JWT for 24 hours — challenge is instantly deleted upon use
```

---

## 7. Cryptographic Parameters

| Parameter | Algorithm |
|---------|-----------|
| KDF | HKDF-SHA256 |
| AEAD | ChaCha20-Poly1305 |
| Key Exchange | X25519 + ML-KEM-768 |
| Transcript Hash | BLAKE3 |
| Signature | Ed25519 |
| HMAC | HMAC-SHA256 |
| Argon2 | Argon2id (m=64MB default, requires `feature = "argon2"`) |
| Constant-Time Compare | `subtle::ConstantTimeEq` |
| Randomness | OS CSPRNG via `getrandom` |

---

## 8. Outside Protocol Scope

| Property | Status | Note |
|---------|--------|----------|
| Full Metadata Protection | ⚠️ Partial | Padding + cover traffic complicates analysis but does not eliminate it |
| Anonymity | ⚠️ Partial | Exclusively through Tor (`proxy`) |
| MITM Prevention on first contact | ⚠️ Partial | TOFU — requires out-of-band verification of Safety Numbers |
| Transport Security | ❌ | Application is entirely responsible for TLS |
| Timing Oracle in Rate Limiter | ⚠️ Partial | Complete structural fix deferred |

---

## 9. Reliable Routing via WebSocket (Delivery ACKs & Reliability)

Introduced in version `3.0.0`, a strict architectural rule guarantees reliable message delivery and resilience against unexpected network interruptions:
- **Server ACKs**: The server implements a strict (Store-and-Forward) policy. Any incoming message is natively written to the sled database (`tree_queue`) with a 7-day TTL prior to socket transmission. The message is **never** dropped from the server queue until an explicit client acknowledgment is provided:
  `{"type": "ack", "message_id": "<uuid>"}`
- **Last Resort PreKey**: To mitigate One-Time key starvation for offline nodes facing an influx of messages, the client uploads a designated `is_last_resort` bundle (`prekey_resort:<id>`) which the server never deletes upon fetching.
- **WebRTC Fast-path**: The server identifies `{"type": "webrtc", "signal": {...}}` metadata, routing SDP Offers and ICE Candidates with a substantially constrained TTL (60 seconds) to inherently prevent phantom rings (Ghost calls) for nodes that reconnect hours later.

