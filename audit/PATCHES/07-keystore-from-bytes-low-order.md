# Patch 07 — `IdentityKeyPair::from_bytes` rejects low-order X25519
**Finding:** SIBNA-2026-007 (low-order X25519)
**File:** `core/src/keystore/mod.rs`

```diff
 pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeystoreError> {
     // ... parse out X25519 public, Ed25519 public, Ed25519 secret ...
+
+    // Reject low-order X25519 at the boundary.
+    if is_low_order_x25519(&x25519_public) {
+        return Err(KeystoreError::InvalidKey);
+    }
+
     // Ed25519 secret must derive to Ed25519 public.
     let derived_ed = ed25519_dalek::SecretKey::from_bytes(&ed25519_secret)
         .ok()
         .map(|s| ed25519_dalek::PublicKey::from(&s).to_bytes());
     if derived_ed.as_ref() != Some(&ed25519_public) {
         return Err(KeystoreError::InvalidKey);
     }
     // ... rest unchanged
 }
```

The `is_low_order_x25519` helper is the same one used in Patch 06.

**Verification:** `keystore::tests::test_keystore` and
`test_keystore_disk_roundtrip` pass; manually crafted low-order
public keys are now rejected.
