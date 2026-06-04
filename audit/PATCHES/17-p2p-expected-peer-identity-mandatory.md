# Patch 17 — P2P `expected_peer_identity` is now mandatory (SIBNA-2026-020)
**Finding:** SIBNA-2026-020 (P2P warn-only identity check)
**File:** `core/src/p2p/handshake.rs`
**Date:** June 2026

## Problem
The P2P handshake in `core/src/p2p/handshake.rs` checked the
responder's Ed25519 identity against `P2pConfig::expected_peer_identity`,
but only if that field was set. If unset, the code emitted a
`tracing::warn!` and proceeded with the connection.

This was a footgun: a default `P2pConfig` (i.e., no out-of-band
identity exchange) silently disabled MITM protection. An active
attacker could substitute their own bundle in the P2P `Hello` /
`Bundle` exchange and recover the session.

## Fix
Made the check mandatory. The handshake now returns
`P2pError::Handshake("no expected_peer_identity configured...")`
if the field is unset. Production callers MUST pre-exchange peer
identities (e.g., via safety-number QR codes) and set this field
before initiating a P2P connection.

```diff
-        if let Some(ref expected) = handshake_cfg.expected_peer_identity {
-            if stealth_bundle.responder_ed25519_pub != *expected {
-                return Err(P2pError::Handshake(format!(
-                    "peer identity mismatch: expected={} got={}",
-                    hex::encode(&expected[..4]),
-                    hex::encode(&stealth_bundle.responder_ed25519_pub[..4])
-                )));
-            }
-        } else {
-            tracing::warn!(
-                "P2P initiator: no expected_peer_identity configured. \
-                 MITM protection is DISABLED for this connection. \
-                 Verify safety numbers out-of-band after connection."
-            );
-        }
+        match handshake_cfg.expected_peer_identity {
+            Some(ref expected) => {
+                if stealth_bundle.responder_ed25519_pub != *expected {
+                    return Err(P2pError::Handshake(format!(
+                        "peer identity mismatch: expected={} got={}",
+                        hex::encode(&expected[..4]),
+                        hex::encode(&stealth_bundle.responder_ed25519_pub[..4])
+                    )));
+                }
+            }
+            None => {
+                return Err(P2pError::Handshake(
+                    "no expected_peer_identity configured. \
+                     P2P connections require an out-of-band identity \
+                     verification (safety number exchange) to prevent MITM. \
+                     Set P2pConfig::expected_peer_identity to the peer's \
+                     known Ed25519 key."
+                        .to_string(),
+                ));
+            }
+        }
```

## Test updates
The existing P2P integration tests used `P2pConfig::default()` without
setting `expected_peer_identity`. They were updated in
`tests/integration_tests.rs` to:

1. Generate the peer's identity first.
2. Pass the peer's Ed25519 key to the initiator's `P2pConfig`.
3. Pass the initiator's Ed25519 key to the responder's `P2pConfig`.

This is the correct pattern: peers pre-exchange identities (e.g., via
a QR code) before establishing the P2P connection.

Updated tests:
- `test_hybrid_routing_fallback` (lines ~491–540)
- `test_p2p_pq_handshake_hybrid` (lines ~547–580)

The earlier test pattern of "connect without identity check" is no
longer valid — and is exactly the MITM vulnerability this patch fixes.

## Verification
- `cargo test --lib -p sibna-core` — 136/136 pass.
- `cargo test -p sibna-tests --test integration_tests test_hybrid_routing_fallback` — pass.
- `cargo test -p sibna-tests --test attack_tests run_all_security_audits` — all 12 audits pass.

## Note on default behavior
The `P2pConfig::default()` and `P2pHandshakeConfig::default()` still
set `expected_peer_identity: None`. This is intentional: it forces
the caller to make a conscious decision (set the field or accept the
error). A future enhancement could add a "permissive mode" with a
`#[deprecated]` marker, but for now the strict-by-default behavior is
the right security posture.
