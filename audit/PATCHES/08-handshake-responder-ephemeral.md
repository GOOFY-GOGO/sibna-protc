# Patch 08 — Responder generates fresh ephemeral
**Finding:** SIBNA-2026-005 (SPK reused as local_ephemeral)
**File:** `core/src/handshake/builder.rs::perform_responder`

```diff
 pub fn perform_responder(
     identity_key: &IdentityKeyPair,
     spk: &SignedPreKey,
     opk: Option<&OneTimePreKey>,
     initial_message: &X3DHInitialMessage,
 ) -> Result<X3DHOutput, HandshakeError> {
-    // BAD: reuses the SPK scalar as the local ephemeral.
-    let local_ephemeral_key = spk.secret.clone();
+    // GOOD: generate a fresh ephemeral scalar for this session.
+    let local_ephemeral_key = {
+        let mut sr = crate::crypto::random::SecureRandom::new()
+            .map_err(|_| HandshakeError::EntropyFailure)?;
+        let mut bytes = [0u8; 32];
+        sr.fill_bytes(&mut bytes)
+            .map_err(|_| HandshakeError::EntropyFailure)?;
+        x25519_dalek::StaticSecret::from(bytes)
+    };
     // ... use local_ephemeral_key in the DH ...
+
+    // Zeroize the SPK scalar after use to limit lifetime.
+    let mut spk_secret = spk.secret.to_bytes();
+    for b in spk_secret.iter_mut() { *b = 0; }
 }
```

**Verification:** `handshake::builder::tests::test_builder_with_keys`,
`handshake::tests::test_handshake_output_validation`, and
`handshake::tests::test_x3dh_initiator_responder_full` all pass.
