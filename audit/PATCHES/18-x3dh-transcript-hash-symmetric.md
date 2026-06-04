# Patch 18 — X3DH internal transcript hash was asymmetric (SIBNA-2026-037)
**Finding:** SIBNA-2026-037 (P2P local-connect round-trip fails when
device IDs are non-zero)
**Files:** `core/src/handshake/x3dh.rs`,
`tests/integration_tests.rs::test_p2p_local_connect_and_handshake`
**Date:** June 2026

## Problem

`test_p2p_local_connect_and_handshake` failed with `decrypt:
AuthenticationFailed` whenever the P2P test was updated to pin
`expected_peer_identity` on both sides (SIBNA-2026-020 enforcement,
PATCHES/17). The same defect also broke
`test_p2p_pq_handshake_hybrid` and the
`test_hybrid_routing_fallback` direct-P2P path.

### Root cause

`x3dh_initiator_v3` and `x3dh_responder_v3` in
`core/src/handshake/x3dh.rs` hashed the two device IDs in opposite
order when building the internal transcript hash.

**Initiator** (x3dh.rs:133–143, before this patch):
```rust
hasher.update(our_device_id);   // alice_dev
hasher.update(peer_device_id);  // bob_dev
```

**Responder** (x3dh.rs:283–284, before this patch):
```rust
hasher.update(our_device_id);   // bob_dev
hasher.update(peer_device_id);  // alice_dev
```

So the internal transcript hash was:

- Initiator: `H(alice_id ‖ alice_eph ‖ bob_id ‖ bob_spk ‖ opt(bob_opk) ‖ alice_dev ‖ bob_dev)`
- Responder: `H(alice_id ‖ alice_eph ‖ bob_id ‖ bob_spk ‖ opt(bob_opk) ‖ bob_dev ‖ alice_dev)`

The two differ whenever `alice_dev ≠ bob_dev`. Through the HKDF
binding step (`HKDF-Extract(salt=transcript_ext, ikm=transcript_int)`)
and the subsequent `X3dhKdf::derive_shared_secret`, this caused the
two sides to derive **different shared secrets**. The Double Ratchet
session then keyed off different chain keys, and the very first
`s.send_message` / `r.recv_message` round-trip produced an
`AuthenticationFailed` AEAD error.

### Why the existing unit tests didn't catch this

The two existing X3DH unit tests
(`test_x3dh_initiator_responder_full`,
`test_pq_x3dh_hybrid_full`) both pass `[0u8; 16]` for both device
IDs. With both device IDs equal to all zeros, swapping the order
produces an identical byte stream and the bug is invisible. The
production P2P test was the only place that used distinct,
runtime-generated device IDs.

## Fix

Aligned the responder's internal transcript-hash order with the
initiator's: `[peer_id, peer_eph, our_id, our_spk, opt(our_opk),
peer_device_id, our_device_id]`. This is the responder's view of
the initiator's `[our_id, our_eph, peer_id, peer_spk, opt(peer_opk),
our_device_id, peer_device_id]` — i.e. `our ↔ peer` swap on the
initiator's view, which is the natural mirror for the responder.

```diff
--- a/core/src/handshake/x3dh.rs
+++ b/core/src/handshake/x3dh.rs
@@ in x3dh_responder_v3 …
-    hasher.update(our_device_id);
-    hasher.update(peer_device_id);
+    // Order MUST match x3dh_initiator_v3 exactly, otherwise the two sides derive
+    // different transcript hashes and (via HKDF) different shared secrets.
+    // The initiator's order is: [our_id, our_eph, peer_id, peer_spk, opt(peer_opk),
+    //                           our_device_id, peer_device_id].
+    // From the responder's perspective this is:
+    //   [peer_id, peer_eph, our_id, our_spk, opt(our_opk),
+    //    peer_device_id, our_device_id].
+    hasher.update(peer_device_id);
+    hasher.update(our_device_id);
```

## Test updates

### 1. `test_p2p_local_connect_and_handshake` (PATCHES/17 follow-up)

Was previously marked as a known regression with a long comment
about a "transcript binding bug". Updated to follow the same
`expected_peer_identity` pattern as `test_hybrid_routing_fallback`
and `test_p2p_pq_handshake_hybrid`: generate identities on both
contexts first, then pin each peer's Ed25519 key on the other's
`P2pConfig`. Now passes.

### 2. New unit regression test
`core/src/handshake/x3dh.rs::tests::test_x3dh_initiator_responder_distinct_device_ids`

Uses distinct, non-zero device IDs (`0xA1…0xB0` and `0xB1…0xC0`)
and a non-zero `transcript_ext` to exercise the exact code path
that was broken. Without the fix, this test fails with
`assert!(verify_shared_secret(&result_a, &result_b))`.

## Verification

| Suite | Pre-patch | Post-patch |
|---|---|---:|
| `core` lib unit tests | 136/136 | **137/137** ✅ |
| `attack_tests::run_all_security_audits` (12 vectors) | 12/12 | **12/12** ✅ |
| `multi_device_tests` | 3/3 | **3/3** ✅ |
| `integration_tests` (excl. mDNS) | some failing | **29/29** ✅ |
| `cargo check --workspace` | 0 errors | **0 errors** ✅ |

Specifically:
- `test_p2p_local_connect_and_handshake` — now **PASS** (was FAIL).
- `test_p2p_pq_handshake_hybrid` — now **PASS** (was FAIL).
- `test_hybrid_routing_fallback` — continues to pass.
- `test_x3dh_initiator_responder_distinct_device_ids` (NEW) — **PASS**.

## Related findings (out of scope for this patch)

- **SIBNA-2026-030** (P2P uses different handshake from X3DH): the
  P2P path and the server-X3DH path now share the same internal
  X3DH transcript construction. With this fix the P2P
  transcript-binding chain is:

  ```
  P2P-Hello-ephemeral
    ←  P2P external transcript
      →  HKDF-Extract(salt=ext, ikm=int)
        →  X3DH internal transcript
          →  derive_shared_secret (or derive_pq_shared_secret)
            →  shared_secret
              →  ratchet.from_shared_secret
  ```

  The P2P external transcript binds the P2P Hello ephemeral
  (used to derive the `handler` AEAD for the encrypted bundle and
  envelope) to the X3DH internal transcript (which contains the
  X3DH ephemeral, identities, SPK, and device IDs). HKDF
  cryptographically couples them. An active attacker cannot swap
  the X3DH envelope without also being able to substitute the
  P2P Hello ephemeral, which is detected by the identity pin
  (SIBNA-2026-020).

- **PQC transcript salt**: with the `pqc` feature enabled, the
  shared-secret derivation in both `x3dh_initiator_v3` and
  `x3dh_responder_v3` still uses the bare internal
  `transcript_hash` as the HKDF salt rather than the
  `combined_transcript` (the HKDF of internal × external). The
  non-PQC cfg path uses `combined_transcript`. This is a separate
  minor weakness (the external P2P binding is therefore not
  transitively sealed into the KDF output when PQC is enabled),
  but it does not affect the bug fixed in this patch — both sides
  now compute the same `transcript_hash` and therefore the same
  shared secret. Tracked as a follow-up.
