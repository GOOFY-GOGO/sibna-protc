# Patch 10 — Storage manifest is mandatory
**Finding:** SIBNA-2026-011 (manifest optional; deletion defeats rollback)
**File:** `core/src/storage.rs`

```diff
 #[derive(Serialize, Deserialize)]
 pub struct StoragePayload {
     pub version: u32,
     pub ciphertext: Vec<u8>,
     pub nonce: [u8; NONCE_LENGTH],
     pub salt: Option<[u8; 32]>,
     pub device_id: [u8; 16],
     pub created_at: u64,
-    pub manifest: Option<Manifest>,
+    pub manifest: Manifest,  // mandatory; legacy un-protected saves must be migrated
 }
```

```diff
 pub fn load_context(
     path: &Path,
 ) -> Result<(StoragePayload, LockGuard), StorageError> {
     let raw = std::fs::read(path)?;
     let payload: StoragePayload = bincode::serde::decode_from_slice(&raw, bincode::config::legacy())
         .map_err(|_| StorageError::Corrupted)?
         .0;
+    // Manifest is mandatory; an empty/missing manifest is rejected.
+    if payload.manifest.is_empty() {
+        return Err(StorageError::Corrupted);
+    }
     Ok((payload, lock))
 }
```

**Migration note:** existing un-protected saves (saved with the
pre-patch `Option<Manifest>`) will fail to load with
`StorageError::Corrupted`. Users must re-protect their keystore.

**Verification:** `storage::tests::test_manifest_required` (new test)
and `keystore::tests::test_keystore_disk_roundtrip` pass.
