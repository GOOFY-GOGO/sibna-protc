# Patch 13 — Test updates for new behavior
**Findings:** SIBNA-2026-001, SIBNA-2026-007
**Files:** `core/src/crypto/mod.rs`, `core/src/keystore/mod.rs`

## `core/src/crypto/mod.rs::tests::test_empty_plaintext` (was failing)
Now updated to assert the **new** behavior:
```diff
 #[test]
 fn test_empty_plaintext() {
     let key = [0x42u8; 32];
     let handler = CryptoHandler::new(&key).unwrap();
-    assert!(handler.encrypt(b"", b"").is_err());
-    assert!(handler.decrypt(&[], b"").is_err());
+    let ct = handler.encrypt(b"", b"").expect("empty plaintext should encrypt");
+    assert_eq!(ct.len(), NONCE_LENGTH + TAG_LENGTH);
+    let pt = handler.decrypt(&ct, b"").expect("empty plaintext should decrypt");
+    assert!(pt.is_empty());
 }
```

## `core/src/keystore/mod.rs::tests::test_verify_signed_challenge_invalid`
```diff
 #[test]
 fn test_verify_signed_challenge_invalid() {
     // ... build a keypair with a corrupted signature ...
-    assert!(keypair.verify_signed_challenge(&challenge, &bad_sig).is_ok());
-    assert!(!keypair.verify_signed_challenge(&challenge, &bad_sig).unwrap());
+    let r = keypair.verify_signed_challenge(&challenge, &bad_sig);
+    assert!(matches!(r, Err(KeystoreError::InvalidSignature)));
 }
```

**Verification:** Both tests pass post-patch; previously failing
baseline behavior is now correct.
