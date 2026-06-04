# Patch 22 — `deserialize_state` makes the session fully send-ready (SIBNA-2026-014)
**Finding:** SIBNA-2026-014 (deserialized session could not send)
**File:** `core/src/ratchet/session.rs`
**Date:** June 2026

## Problem

`DoubleRatchetSession::new()` returns a fresh session with
`dh_local: Some(...)` (random), `dh_remote: None`,
`sending_chain: None`, `receiving_chain: None`. The intended
usage is to immediately call `from_shared_secret(...)` to populate
the chains and peer DH key, or to call `deserialize_state(...)` to
restore a previously-serialized session.

`serialize_state` saves:
- `root_key`, `sending_chain`, `receiving_chain`
- `dh_local_bytes` (the **public** part of the local DH key — the
  private scalar is intentionally not persisted)
- `dh_remote_bytes`
- `skipped_message_keys`, counters, version, timestamps

It does **not** save `dh_remote` (the `Option<PublicKey>` field is
`#[serde(skip)]`) and does **not** save the `dh_local` private
scalar.

The pre-PATCH-22 `deserialize_state` simply wrote the loaded
state back into the session — but the deserializer never
re-hydrated the `dh_remote` field from `dh_remote_bytes`, so the
restored session had `dh_remote: None`. Worse, `dh_local: None`
on the restored session (since the private scalar is never
persisted) caused `encrypt()` to fail with `InvalidState` because
the header construction requires `dh_local`.

## Fix

Two changes in `DoubleRatchetSession::deserialize_state`:

1. **Re-hydrate `dh_remote` from `dh_remote_bytes`**
   via `DoubleRatchetState::restore_dh_keys` (already exists on
   `state.rs` — was just never called from `session.rs`).

2. **Trigger a fresh DH ratchet if needed** so the session is
   fully ready to send. The ratchet:
   - Generates a fresh ephemeral `dh_local`.
   - Performs `DH(new_local, dh_remote)` to derive a new
     `root_key` and `sending_chain`.
   - The peer's session will detect the new `dh_public` in the
     header and perform its own ratchet to match — which is the
     correct, spec-compliant behavior for a session restored
     mid-conversation.

The ratchet is only performed when ALL of these hold:
- `dh_local.is_none()` (always true after restore)
- `dh_remote.is_some()` (we have a peer to ratchet against)
- `sending_chain.is_some()` (we have a chain to rotate; otherwise
  the ratchet would create one and orphan the original setup)

```diff
 pub fn deserialize_state(&self, data: &[u8]) -> ProtocolResult<()> {
-    let loaded: DoubleRatchetState = …;
+    let mut loaded: DoubleRatchetState = …;
+
+    // Re-hydrate dh_remote from dh_remote_bytes.
+    loaded.restore_dh_keys().map_err(|_| …)?;
+
     {
         let mut state = self.state.write();
         *state = loaded;
+        if state.dh_local.is_none()
+            && state.dh_remote.is_some()
+            && state.sending_chain.is_some()
+        {
+            self.perform_dh_ratchet(&mut state)?;
+        }
         …
     }
     Ok(())
 }
```

## Test

New regression test
`ratchet::session::tests::test_serialize_deserialize_roundtrip_can_send`:

1. Establish a real session between Alice (initiator) and Bob
   (responder) via `from_shared_secret`.
2. Alice sends 1 message; Bob decrypts.
3. Alice serializes her state.
4. A fresh `DoubleRatchetSession::new()` is created and
   `deserialize_state` is called with Alice's serialized bytes.
5. The restored Alice encrypts a second message; Bob decrypts it
   correctly.
6. Bob replies; the restored Alice decrypts the reply correctly.

Without the fix, step 5 fails with
`InvalidState`. With the fix, all 6 steps pass.

## Verification

| Suite | Pre-patch | Post-patch |
|---|---:|---:|
| `core` lib unit tests | 144/144 | **145/145** ✅ (+1 roundtrip regression) |
| `attack_tests::run_all_security_audits` | 12/12 | **12/12** ✅ |
| `multi_device_tests` | 3/3 | **3/3** ✅ |
| `integration_tests` (excl. mDNS) | 29/29 | **29/29** ✅ |
| `cargo check --workspace` | 0 errors | **0 errors** ✅ |

## Out-of-scope follow-ups

- **API ergonomics**: `DoubleRatchetSession::new()` followed by
  `deserialize_state` is a 2-step restore. A future
  `DoubleRatchetSession::from_serialized(data, config)` constructor
  could collapse these into one call and prevent the
  "forgot to deserialize" footgun.
- **`set_peer_id` / `session_id` persistence**: `session_id` and
  `peer_id` are not serialized today. If app code uses them as a
  key for local caching, the restored session will look "new" to
  the cache. A future patch could add them to the serialized
  state.
- **Side-channel**: `perform_dh_ratchet` (and therefore
  `deserialize_state`) does a fresh `DH(dh_local, dh_remote)`. If
  the peer's `dh_remote` is the *old* value (e.g., the peer
  hasn't re-ratcheted yet), the DH is still valid — the ratchet
  is forward-secure by design. No security regression.
