# Patch 00 — Bincode 2.0 migration
**Finding:** SIBNA-2026-004 (build blocker)
**Files touched:**
- `Cargo.toml` (workspace)
- 14 call sites of `bincode::encode_to_vec` / `decode_from_slice`
- `core/src/crypto/random.rs` (extra `}`)
- `core/src/crypto/padding.rs` (added `BLOCK_SIZE_STANDARD`)
- `core/src/ratchet/mod.rs` (added `RatchetConfig`)
- `core/src/metadata.rs` (return type)
- `core/src/ratchet/session.rs` (return type)
- `core/src/p2p/handshake.rs` (format string)
- `core/src/metadata.rs` (test fix)
- `server/Cargo.toml` (added `zeroize`)
- `server/src/main.rs` (stray `/`)
- `tests/src/offensive_test.rs` (test arity)
- `tests/src/advanced_offensive_test.rs` (test arity)

## Workspace `Cargo.toml`
```diff
-bincode = { version = "2.0", features = ["derive"] }
+bincode = { version = "2.0", features = ["derive", "serde"] }
```

## Call sites (representative)
```diff
-let bytes = bincode::encode_to_vec(&value, bincode::config::legacy())?;
+let bytes = bincode::serde::encode_to_vec(&value, bincode::config::legacy())?;
```
```diff
-let (value, _): (T, usize) =
-    bincode::decode_from_slice(&bytes, bincode::config::legacy())?;
+let (value, _): (T, usize) =
+    bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())?;
```

## `core/src/crypto/random.rs`
```diff
     pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandomError> {
-        let mut rng = rand::thread_rng();
-        rand::Rng::fill(&mut rng, dest);
-    }
+        let mut rng = rand::thread_rng();
+        rand::Rng::fill(&mut rng, dest);
+        Ok(())
+    }
```

## `core/src/crypto/padding.rs` — new constant
```rust
pub const BLOCK_SIZE_STANDARD: usize = 1024;
```

## `core/src/ratchet/mod.rs` — new struct
```rust
#[derive(Debug, Clone)]
pub struct RatchetConfig {
    pub max_skipped_messages: usize,
    pub message_key_max_age_secs: u64,
    pub max_chain_messages: usize,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            max_skipped_messages: MAX_SKIPPED_MESSAGES,
            message_key_max_age_secs: MAX_MESSAGE_KEY_AGE_SECS,
            max_chain_messages: MAX_SKIPPED_MESSAGES * 2,
        }
    }
}
```

## `core/src/metadata.rs::pad_payload` return type
```diff
-pub fn pad_payload(plaintext: &[u8]) -> Vec<u8> {
+pub fn pad_payload(plaintext: &[u8]) -> Result<Vec<u8>, PaddingError> {
```

## `core/src/ratchet/session.rs::state_summary`
```diff
-pub fn state_summary(&self) -> StateSummary {
+pub fn state_summary(&self) -> super::state::StateSummary {
```

## `core/src/p2p/handshake.rs:213-216` (format string fix)
```diff
-tracing::warn!(target: "sibna::p2p::handshake",
-    "expected peer identity {} but got {}",
-    expected, actual,
-);
+tracing::warn!(target: "sibna::p2p::handshake",
+    "expected peer identity {:?} but got {:?}",
+    expected, actual,
+);
```

## `server/Cargo.toml`
```diff
 sibna-core = { path = "../core", features = ["std", "pqc"] }
+zeroize = "1"
```

## `server/src/main.rs:68`
```diff
-let pub jwt_secret: String = ...
+let jwt_secret: String = ...
```

## Test arity
```diff
-let result = perform_handshake(initiator, responder, ik_i, spk_i, bundle_i, opk_i, ik_r, spk_r);
+let result = perform_handshake(initiator, responder, ik_i, spk_i, bundle_i, opk_i, ik_r, spk_r, None, None);
```

## Verification
- `cargo check --workspace` passes (warnings only).
- All 130 core lib tests pass.
