# Patch 06 — `IdentityKeyPair::is_valid` checks Ed25519 consistency + low-order X25519
**Finding:** SIBNA-2026-007 (low-order X25519 not validated)
**File:** `core/src/keystore/mod.rs`

```diff
 pub fn is_valid(&self) -> bool {
     if self.ed25519_secret == [0u8; 32] { return false; }
     if self.ed25519_public == ed25519_dalek::PublicKey::from(&[0u8; 32]).to_bytes() { return false; }
+
+    // Ed25519 secret → derived public must equal stored public.
+    let derived = ed25519_dalek::SecretKey::from_bytes(&self.ed25519_secret)
+        .ok()
+        .map(|s| ed25519_dalek::PublicKey::from(&s).to_bytes());
+    if derived.as_ref() != Some(&self.ed25519_public) {
+        return false;
+    }
+
+    // X25519 derived from Ed25519 must equal stored X25519 public, AND
+    // the X25519 public must not be a low-order point.
+    let x25519_derived = x25519_dalek::PublicKey::from(&self.x25519_secret).to_bytes();
+    if x25519_derived != self.x25519_public {
+        return false;
+    }
+    if is_low_order_x25519(&self.x25519_public) {
+        return false;
+    }
     true
 }
```

The `is_low_order_x25519` helper rejects the 8 small-subgroup points
(including the all-zero point) before they enter the DH computation.

**Verification:** `keystore::tests::test_identity_keypair_generation`
and `test_verify_signed_challenge_invalid` (updated to expect
`Err(InvalidSignature)`).
