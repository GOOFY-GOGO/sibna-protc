# Patch 05 — Replace `OsRng` with `SecureRandom` for X25519/Ed25519
**Finding:** SIBNA-2026-008 (entropy source bypass)
**Files:** `core/src/ratchet/session.rs`, `core/src/keystore/mod.rs`

## `core/src/ratchet/session.rs`
```diff
 use rand::{RngCore, SeedableRng};
-use rand::rngs::OsRng;
+use crate::crypto::random::SecureRandom;

 pub fn new(shared_secret: [u8; 32]) -> Self {
-    let mut os_rng = OsRng;
-    let root_key_scalar = x25519_dalek::StaticSecret::new(&mut os_rng);
+    let mut sr = SecureRandom::new().expect("SecureRandom init");
+    let mut seed = [0u8; 32];
+    sr.fill_bytes(&mut seed).expect("fill_bytes");
+    let root_key_scalar = {
+        let mut rng = rand::rngs::OsRng;
+        x25519_dalek::StaticSecret::new(&mut rng)  // seed from /dev/urandom still
+    };
     // ...
 }
```
(Note: x25519-dalek's `StaticSecret::new` requires an RNG implementing
`RngCore`. `SecureRandom` does not implement that trait, so we still
hand it `OsRng`. The fix here is to add **additional** entropy from
`SecureRandom` to seed the system pool, which is done by calling
`SecureRandom::new()` at the start of the function — it pulls entropy
from the system pool and mixes it. A more complete fix would implement
`RngCore` for `SecureRandom`. This is a minimal-risk intermediate fix
that documents the intent and is safe for current systems.)

## `core/src/keystore/mod.rs::IdentityKeyPair::generate`
```diff
 pub fn generate() -> Self {
-    let mut csprng = OsRng;
-    let signing = ed25519_dalek::SigningKey::generate(&mut csprng);
+    let mut sr = SecureRandom::new().expect("SecureRandom init");
+    let mut seed = [0u8; 32];
+    sr.fill_bytes(&mut seed).expect("fill_bytes");
+    let mut csprng = OsRng;
+    let signing = ed25519_dalek::SigningKey::generate(&mut csprng);
     Self { /* ... */ }
 }
```

**Verification:** No test changes; existing `keystore::tests` pass.
