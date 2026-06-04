# Patch 12 — Cover traffic `dummy_id` is random
**Finding:** SIBNA-2026-001 (cover traffic hardening)
**File:** `core/src/manager.rs`

```diff
 pub fn generate_cover_message(&mut self) -> Result<EncryptedMessage, ProtocolError> {
-    let dummy_id = [0u8; 32];  // BAD: fingerprint of "no real recipient"
+    // Use a random dummy recipient to avoid the on-wire fingerprint
+    // "always-zero cover recipient".
+    let mut dummy_id = [0u8; 32];
+    let mut sr = crate::crypto::random::SecureRandom::new()
+        .map_err(|_| ProtocolError::EntropyFailure)?;
+    sr.fill_bytes(&mut dummy_id)
+        .map_err(|_| ProtocolError::EntropyFailure)?;
     // ... use dummy_id to construct cover message ...
 }
```

**Verification:** No explicit test added; this is a defensive
hardening for the previously-broken cover traffic path (SIBNA-2026-001).
