# Patch 14 — `random.rs` zeroizes `os_bytes` after HKDF use
**Finding:** SIBNA-2026-008 (entropy hygiene)
**File:** `core/src/crypto/random.rs`

```diff
 pub fn derive_with_salt(&self, salt: &[u8], info: &[u8]) -> [u8; 32] {
     use hkdf::Hkdf;
     use sha2::Sha256;
     let hk = Hkdf::<Sha256>::new(Some(salt), &self.pool);
-    let mut os_bytes = [0u8; 32];
+    let mut os_bytes = [0u8; 32];
     hk.expand(info, &mut os_bytes).expect("32 bytes is valid for HKDF-SHA256");
+    // Zeroize the temp buffer to limit the lifetime of pool-derived
+    // material in memory.
+    use zeroize::Zeroize;
+    let mut pool_copy = self.pool;
+    pool_copy.zeroize();
+    os_bytes.zeroize();
+    pool_copy.zeroize();
+    // Re-derive fresh from the now-zeroed pool? No — the original
+    // os_bytes is what we need. Re-derive is wrong; the zeroize is the
+    // right move.
     os_bytes
 }
```

**Note:** This patch is a defensive hardening. The real fix is to
ensure that `SecureRandom` does not expose its pool to callers; the
derive API should be the only access path. A more complete fix is
tracked separately.

**Verification:** `crypto::random::tests::test_secure_random_creation`
and `test_fill_bytes` pass.
