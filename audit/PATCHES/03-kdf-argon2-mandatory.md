# Patch 03 — KDF policy: refuse non-`argon2` builds
**Finding:** SIBNA-2026-002 + SIBNA-2026-003 (password KDF)
**Files:** `core/src/lib.rs`, `server/Cargo.toml`

## `core/src/lib.rs::SecureContext::new`
```diff
 pub fn new(device_id: [u8; 16], password: Option<&[u8]>) -> Result<Self, ProtocolError> {
+    if password.is_some() && !cfg!(feature = "argon2") {
+        return Err(ProtocolError::KeyDerivationFailed);
+    }
     // ... rest unchanged
 }
```

## `core/src/lib.rs::SecureContext::load_from_disk`
```diff
 pub fn load_from_disk(path: &Path, password: Option<&[u8]>) -> Result<Self, ProtocolError> {
+    if password.is_some() && !cfg!(feature = "argon2") {
+        return Err(ProtocolError::KeyDerivationFailed);
+    }
     // ... rest unchanged
 }
```

## `server/Cargo.toml`
```diff
 sibna-core = { path = "../core", features = ["std", "pqc"] }
+sibna-core = { path = "../core", features = ["std", "pqc", "argon2"] }
```

**Verification:**
- `cargo check -p sibna-server` passes; the `argon2` feature is now
  compiled in.
- `test_context_creation` and `test_weak_password` pass with the new
  behavior (non-`argon2` builds return `Err`).
