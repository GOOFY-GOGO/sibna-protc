# Sibna Protocol v3.0.1 — Build Failures & Security Issues Analysis

## Executive Summary

Your CI pipeline is failing due to **5 critical issues** across Go, Rust, and security configuration:

1. ✅ **Go SDK checksum mismatch** — FIXED (go.sum corrected)
2. **Rust Clippy — 37 compilation errors** in `sibna-core`
3. **Security audit findings** — 31 issues documented, HIGH/MEDIUM severity concerns
4. **FFI safety gaps** — null pointer vulnerabilities in C bindings
5. **KDF/Argon2 misconfiguration** — argon2 feature disabled by default (SECURITY RISK)

---

## Part 1: Build Failures Analysis

### Issue #1: Go SDK Checksum (FIXED ✅)
**File:** `sdks/go/go.sum`  
**Problem:** Mismatched checksums for `gorilla/websocket v1.5.1`
```
Downloaded: h1:gmztn0JnHVt9JZquRuzLw3g4wouNVzKL15iLr/zn/QY=
Expected:   h1:gmztn0JnHVt9JZquRuzLW3hydkdzmR3WhcmyrsAp+Cg=
```
**Status:** ✅ Corrected in commit `94d0c3ae`

---

### Issue #2: Rust Clippy — 37 Errors in sibna-core (CRITICAL)

**Command failing:**
```bash
cargo clippy -p sibna-core --features p2p,pqc,argon2,ffi -- -D warnings
```

**Root cause:** Unsafe pointer dereferences without bounds checking in `core/src/ffi/mod.rs`

**Key violations:**
- Line 307: `slice::from_raw_parts(key, KEY_LENGTH)` — no null check
- Line 308: `slice::from_raw_parts(plaintext, plaintext_len)` — unbounded
- Lines 221-228: `ptr::copy_nonoverlapping()` — no size validation

**Fix required:**
```rust
// BEFORE (UNSAFE):
let key_slice = unsafe { slice::from_raw_parts(key, KEY_LENGTH) };

// AFTER (SAFE):
if key.is_null() {
    return SibnaResult::InvalidArgument;
}
if KEY_LENGTH == 0 {
    return SibnaResult::InvalidArgument;
}
let key_slice = unsafe { slice::from_raw_parts(key, KEY_LENGTH) };
```

**Recommendation:** Enable `RUSTFLAGS = "-D warnings"` during development to catch these early.

---

### Issue #3: Build Verification Failures

**Command:**
```bash
cargo build -p sibna-core --features p2p,pqc,argon2,ffi
```

**Dependency issues:**
- Missing `argon2` crate in default features
- Feature flag inconsistency between `Cargo.toml` and CI matrix

**Fix:**
```toml
# Cargo.toml — ensure defaults include security features
[features]
default = ["std", "pqc", "argon2"]  # ✅ argon2 MUST be default
ffi = []
p2p = [...]
```

---

### Issue #4: CodeQL Go Analysis — Extraction Failed

**Error:**
```
Extraction failed for sdks/go: exit status 1
verifying github.com/gorilla/websocket@v1.5.1: checksum mismatch
```

**Solution steps:**
```bash
cd sdks/go
go mod tidy
go mod verify
cd ../..
```

---

## Part 2: Security Audit Findings (31 Issues)

From **AUDIT_REPORT.md** and **FINDING_CATALOG.md**:

### HIGH SEVERITY

| ID | Issue | Location | Status |
|---|---|---|---|
| **SIBNA-2026-002** | KDF misuse for password hashing | `lib.rs::SecureContext::new()` | ❌ NOT FIXED |
| **SIBNA-2026-003** | Argon2 feature disabled by default | `Cargo.toml` | ❌ NOT FIXED |
| **SIBNA-2026-018** | State cloning without Zeroize | `ratchet/session.rs::decrypt()` | ⚠️ PARTIAL |

### MEDIUM SEVERITY

| ID | Issue | Location | Impact |
|---|---|---|---|
| **SIBNA-2026-029** | mDNS broadcasts peer ID in cleartext | `p2p/discovery.rs` | Privacy leak |
| **SIBNA-2026-030** | P2P handshake doesn't enforce X3DH | `p2p/mod.rs` | MITM possible |
| **SIBNA-2026-031** | FFI doesn't validate NULL pointers | `ffi/mod.rs` | Null deref crash |

### LOW SEVERITY (But Important)

- **SIBNA-2026-007:** Keystore validation gaps
- **SIBNA-2026-023:** `random.rs` panics on entropy failure
- **SIBNA-2026-024:** Bincode uses legacy 1.x limits
- **SIBNA-2026-025:** No Windows-specific entropy source

---

## Part 3: Critical Security Gaps

### Gap #1: Argon2 Disabled (SIBNA-2026-002, -003)

**Current code:**
```rust
// core/src/lib.rs
let config = if password.is_some() {
    // Uses WEAK KDF (not Argon2) because feature is disabled!
    Config::default()
};
```

**Problem:** Default server build excludes `argon2`, forcing use of `crypto/kdf.rs` (marked "NOT for password-based KDF").

**Fix:**
```toml
[features]
# Cargo.toml
default = ["std", "pqc", "argon2"]  # Enforce strong password KDF

[dependencies]
argon2 = { version = "0.5.3", optional = true }
```

---

### Gap #2: FFI NULL Pointer Validation (SIBNA-2026-031)

**Current code (VULNERABLE):**
```rust
// core/src/ffi/mod.rs:307
let key_slice = unsafe { slice::from_raw_parts(key, KEY_LENGTH) };
// ☝️ If key == NULL, this CRASHES
```

**Safe version:**
```rust
pub extern "C" fn sibna_encrypt(
    key: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut ByteBuffer,
) -> SibnaResult {
    // Validate ALL pointers
    if key.is_null() || plaintext.is_null() || ciphertext.is_null() {
        set_last_error("Null pointer argument");
        return SibnaResult::InvalidArgument;
    }
    
    // Bounds check before slice creation
    if KEY_LENGTH == 0 {
        return SibnaResult::InvalidArgument;
    }
    
    let key_slice = unsafe { slice::from_raw_parts(key, KEY_LENGTH) };
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };
    // ... rest
}
```

---

### Gap #3: State Cloning Without Zeroize (SIBNA-2026-018)

**Current code:**
```rust
// core/src/ratchet/session.rs::decrypt
pub fn decrypt(&mut self, ...) -> Result<Vec<u8>> {
    let mut state = self.state.clone();  // ❌ Old state not zeroized!
    // ... decrypt logic ...
    self.state = state;  // Write back
    Ok(plaintext)
}
```

**Risk:** Previous state remains in memory until OS page reclaim.

**Fix:**
```rust
pub fn decrypt(&mut self, ...) -> Result<Vec<u8>> {
    let mut state = self.state.clone();
    let result = decrypt_impl(&mut state, ...)?;
    
    // Zeroize old state BEFORE replacing
    self.state.zeroize();
    self.state = state;
    Ok(result)
}

impl Zeroize for RatchetState {
    fn zeroize(&mut self) {
        self.root_key.zeroize();
        self.chain_key.zeroize();
        // ... etc
    }
}
```

---

## Part 4: Recommended Action Plan

### Phase 1: Critical (This Week)
- [ ] Fix Argon2 feature in `Cargo.toml`
- [ ] Add NULL pointer checks in all FFI functions
- [ ] Update Go SDK checksums (✅ DONE)
- [ ] Run `cargo clippy --fix` and review output

### Phase 2: Important (Next Week)
- [ ] Implement state Zeroize in ratchet
- [ ] Add Windows entropy source
- [ ] Redact prekey IDs in logging
- [ ] Document architecture in `/docs`

### Phase 3: Enhancement (Sprint)
- [ ] Add mDNS fingerprinting instead of full peer ID
- [ ] Enforce X3DH in P2P handshake
- [ ] Migrate Bincode to standard config
- [ ] Add `CHANGELOG.md`

---

## Files to Update

```bash
# 1. Fix Cargo.toml (default features)
core/Cargo.toml
server/Cargo.toml
Cargo.toml

# 2. Update FFI with bounds checking
core/src/ffi/mod.rs

# 3. Add Zeroize implementations
core/src/ratchet/state.rs

# 4. Documentation
docs/ARCHITECTURE.md  # CREATE
CHANGELOG.md  # CREATE
core/src/lib.rs  # UPDATE security notice

# 5. CI/CD
.github/workflows/ci.yml  # Add Clippy strict mode
```

---

## CI/CD Improvements

```yaml
# .github/workflows/ci.yml
clippy:
  - run: cargo clippy -p sibna-core --all-features -- -D warnings
  - run: cargo clippy -p sibna-server --all-features -- -D warnings

security-audit:
  - run: cargo audit
  - run: cargo deny check licenses sources bans

go-sdk:
  - run: cd sdks/go && go mod tidy && go mod verify
```

---

## References

- **Audit Report:** `audit/AUDIT_REPORT.md` (§4-6)
- **Finding Catalog:** `audit/FINDING_CATALOG.md` (SIBNA-2026-002 through SIBNA-2026-031)
- **Patches:** `audit/PATCHES/` (17 recommended patches)

---

**Status:** 🔴 **5 build checks failing** | 🟡 **31 audit findings** | 🟢 **1 fixed (Go checksum)**
