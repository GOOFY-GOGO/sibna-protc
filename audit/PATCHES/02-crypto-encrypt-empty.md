# Patch 02 — `CryptoHandler::encrypt` allows empty plaintext
**Finding:** SIBNA-2026-001 (cover traffic)
**File:** `core/src/crypto/mod.rs`

```diff
 pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> CryptoResult<Vec<u8>> {
-    if plaintext.is_empty() {
-        return Err(CryptoError::InvalidPlaintext);
-    }
     // ... rest unchanged
 }
```

Also updated `decrypt` length check (was rejecting 28-byte ciphertext):
```diff
-    if ciphertext.len() < MIN_CIPHERTEXT_LENGTH {
+    if ciphertext.len() < NONCE_LENGTH + TAG_LENGTH {
         return Err(CryptoError::InvalidCiphertext);
     }
```
And `decrypt_in_place` got the same treatment.

**Verification:**
- `crypto::tests::test_empty_plaintext` passes.
- `crypto::encryptor::tests::test_empty_plaintext` passes.
