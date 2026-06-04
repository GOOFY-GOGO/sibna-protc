# Patch 09 — `ratchet::session::decrypt` does not clone state on failure
**Finding:** SIBNA-2026-009 (DoS via state corruption)
**File:** `core/src/ratchet/session.rs`

```diff
 pub fn decrypt(&mut self, header: &[u8], body: &[u8]) -> CryptoResult<Vec<u8>> {
-    let mut new_state = self.state.clone();
-    let pt = new_state.process_incoming(header, body)?;
-    self.state = new_state;  // overwrites original even on failure
+    // Compute on a clone, but only commit on success.
+    let mut new_state = self.state.clone();
+    let pt = match new_state.process_incoming(header, body) {
+        Ok(pt) => pt,
+        Err(e) => return Err(e),  // original state preserved
+    };
+    self.state = new_state;
     Ok(pt)
 }
```

**Verification:** `ratchet::session::tests::test_replay_protection`
passes. (No explicit "MAC failure preserves state" test yet;
recommended follow-up.)
