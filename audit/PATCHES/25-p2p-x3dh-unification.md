# PATCH 25 — Unify P2P handshake with X3DH

**Finding:** SIBNA-2026-030
**Severity:** MEDIUM
**Date:** 2026-06-03

## Problem

The P2P handshake (`core/src/p2p/handshake.rs`) used a different
construction from the server-mediated X3DH path (`core/src/handshake/x3dh.rs`):

1. **Two separate ephemeral keys**: Alice generated `alice_ephemeral` for
   transport encryption AND a separate `x3dh_ephemeral` for X3DH. X3DH
   uses only ONE ephemeral.

2. **Different transcript construction**: P2P hashed `alice_ephemeral +
   bob_ephemeral + both_device_ids + both_identity_keys`. X3DH hashes
   `identity + ephemeral + signed_prekey + opk + device_ids`.

3. **Extra transport encryption layer**: `derive_handshake_key()` based
   on separate ephemeral keys. X3DH relies on the KDF.

The mismatch meant the `transcript_hash_ext` binding was not a no-op —
it combined two different hashes, creating an inconsistency between the
P2P and server-mediated X3DH flows.

## Solution

### Single ephemeral key

Each side now generates ONE ephemeral key that serves double duty:
- Transport encryption (Hello/Bundle/Envelope/Ok messages)
- X3DH key agreement (DH2, DH3, and optionally DH4)

This matches X3DH's design where a single ephemeral participates in
all DH operations.

### X3DH-aligned transcript

Added `build_transcript()` function that constructs the P2P transcript
using the **exact same inputs and order** as `x3dh_initiator_v3` /
`x3dh_responder_v3` internal transcript:

```
initiator_identity, initiator_ephemeral, responder_identity,
responder_signed_prekey, responder_onetime_prekey (optional),
initiator_device_id, responder_device_id
```

Since both sides now compute the same transcript, the HKDF combination
in X3DH produces a consistent result regardless of whether the flow
is P2P or server-mediated.

### Changes

**`core/src/p2p/handshake.rs`:**

- Added `build_transcript()` function matching X3DH's internal transcript
- Removed `StealthEnvelope.ephemeral_pub` field (the Hello ephemeral IS
  the X3DH ephemeral — no separate key needed)
- `derive_handshake_key()` KDF label bumped from `v3` to `v4`
- `P2P_PROTOCOL_VERSION` bumped from `3` to `4` (wire-breaking change)
- Initiator: removed separate `x3dh_ephemeral` generation; uses
  `alice_ephemeral` directly for X3DH
- Responder: removed `stealth_envelope.ephemeral_pub` usage; uses
  `alice_ephemeral_pub` directly for X3DH

### Wire protocol changes

| Field | v3 | v4 |
|-------|----|----|
| `Hello.ephemeral_pub` | Transport-only | Transport + X3DH |
| `Bundle.ephemeral_pub` | Transport-only | Transport + X3DH |
| `StealthEnvelope.ephemeral_pub` | Separate X3DH key | Removed |
| Protocol version | 3 | 4 |

## Backward Compatibility

This is a **wire-breaking change**. Nodes running v4 cannot handshake
with nodes running v3. This is acceptable for a major version bump
(v3.0.0 → v3.1.0 or v4.0.0).

## Verification

- `cargo check --workspace` — clean (0 errors)
- `cargo test --lib -p sibna-core` — 145/145 passed
- `cargo test --test integration -p sibna-core -- --skip mdns` — 14/14 passed
- `cargo test --test attack_tests -p sibna-tests` — 1/1 passed

## Security Impact

- **Before**: P2P and X3DH had inconsistent transcript bindings, creating
  a subtle divergence in key derivation
- **After**: Both paths produce identical transcript hashes, ensuring the
  HKDF binding step is a true no-op (identity operation) for the combined
  transcript, matching the intended design

## Remaining Notes

- The `combined_transcript` variable in `x3dh_initiator_v3` (line 158)
  and `x3dh_responder_v3` (line 295) is now unused (warning) because the
  P2P transcript is passed as `transcript_hash_ext` and the internal
  transcript is identical. This is correct — the HKDF-Extract with
  identical inputs produces a valid binding.
