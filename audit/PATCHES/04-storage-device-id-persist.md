# Patch 04 — Persist `device_id` in storage payload
**Finding:** SIBNA-2026-010 (device_id zeroed on load)
**Files:** `core/src/storage.rs`, `core/src/lib.rs`

## `core/src/storage.rs::StoragePayload`
```diff
 pub struct StoragePayload {
     pub version: u32,
     pub ciphertext: Vec<u8>,
     pub nonce: [u8; NONCE_LENGTH],
     pub salt: Option<[u8; 32]>,
+    pub device_id: [u8; 16],
     pub created_at: u64,
     pub manifest: Manifest,  // was: Option<Manifest>; see Patch 10
 }
```

## `core/src/storage.rs::save_context`
```diff
 pub fn save_context(
     path: &Path,
+    device_id: [u8; 16],
     ciphertext: &[u8],
     nonce: &[u8; NONCE_LENGTH],
     salt: Option<&[u8; 32]>,
     manifest: &Manifest,
 ) -> Result<(), StorageError> {
     // ...
     StoragePayload {
         version: 1,
         ciphertext: ciphertext.to_vec(),
         nonce: *nonce,
         salt: salt.copied(),
+        device_id,
         created_at: now,
         manifest: manifest.clone(),
     }
 }
```

## `core/src/lib.rs::SecureContext::save_to_disk`
```diff
 pub fn save_to_disk(&self, path: &Path) -> Result<(), ProtocolError> {
-    save_context(path, &self.ciphertext, &self.nonce, self.salt.as_ref(), &self.manifest)
+    save_context(path, self.device_id, &self.ciphertext, &self.nonce, self.salt.as_ref(), &self.manifest)
 }
```

## `core/src/lib.rs::SecureContext::load_from_disk`
```diff
 pub fn load_from_disk(path: &Path, password: Option<&[u8]>) -> Result<Self, ProtocolError> {
-    let mut ctx = ... ;
-    ctx.device_id = [0u8; 16];
+    let mut ctx = ... ;
+    ctx.device_id = payload.device_id;  // restore from saved blob
     Ok(ctx)
 }
```

**Verification:** `keystore::tests::test_keystore_disk_roundtrip` passes.
