# Patch 01 — `padding::pad_message` allows empty plaintext
**Finding:** SIBNA-2026-001 (cover traffic)
**File:** `core/src/crypto/padding.rs`

```diff
 pub fn pad_message(plaintext: &[u8], block_size: usize) -> Result<Vec<u8>, PaddingError> {
-    if plaintext.is_empty() {
-        return Err(PaddingError::EmptyPlaintext);
-    }
     if block_size < MIN_BLOCK_SIZE {
         return Err(PaddingError::InvalidBlockSize);
     }
     if block_size > MAX_BLOCK_SIZE {
         return Err(PaddingError::InvalidBlockSize);
     }
     // ... rest unchanged
 }
```

**Verification:** `crypto::padding::tests::test_pad_unpad_roundtrip` and
`test_empty_plaintext` (added in core/crypto/mod.rs) pass.
