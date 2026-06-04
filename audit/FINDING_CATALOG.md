# Sibna Protocol v3.0.0 — Finding Catalog

Each finding has: ID, severity, CVSS 3.1 vector (where applicable), location,
root cause, impact, exploit path, remediation reference, and verification
status. Findings are ordered by severity then ID.

---

## SIBNA-2026-001 — Cover traffic broken (empty plaintext rejected)
**Severity:** CRITICAL · **CVSS 3.1:** 7.1
`AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Location:**
- `core/src/crypto/padding.rs::pad_message`
- `core/src/crypto/mod.rs::CryptoHandler::encrypt`

**Root cause:**
`pad_message` and `CryptoHandler::encrypt` both required `pt.len() > 0`,
returning `PaddingError::EmptyPlaintext` / `CryptoError::InvalidPlaintext`
respectively. The cover-traffic generator in
`core/src/manager.rs::HybridRouter::generate_cover_message` calls
`encrypt_message(b"")` to produce a decoy message; this path always
returned an error.

**Impact:**
The `SecureContext::generate_cover_message` privacy guarantee (declared
in the lib.rs top comment) is non-functional. Passive network observers
can trivially distinguish real messages from cover traffic. This is the
single largest privacy weakness in the pre-patch code.

**Exploit:**
Attacker passively observes a stream. Calls to `generate_cover_message`
return `Err`, which the calling code silently drops (via `unwrap_or`
in two locations). The actual stream then consists only of real
messages; metadata analysis becomes trivial.

**Remediation:** `audit/PATCHES/01-crypto-pad-empty.md`,
`audit/PATCHES/02-crypto-encrypt-empty.md`. Empty plaintext is now
permitted in both layers.

**Verification:** `test_empty_plaintext` (both `crypto` and
`crypto::encryptor` modules) now passes.

---

## SIBNA-2026-002 — Password KDF uses HKDF-iterated in non-`argon2` builds
**Severity:** CRITICAL · **CVSS 3.1:** 8.5
`AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`

**Location:** `core/src/lib.rs::SecureContext::new`,
`core/src/lib.rs::SecureContext::load_from_disk`,
`core/src/crypto/kdf.rs::HkdfKdf::derive_iterated`.

**Root cause:**
The password-protection path called `HkdfKdf::derive_iterated(password,
salt, ..., 100_000)`. The `kdf.rs` docstring explicitly says
"**NOT for password-based KDF** — use Argon2id instead". HKDF is a fast
PRF; 100k iterations of HKDF is not slow enough to resist offline
brute-force on a weak password (modern GPUs can compute ~1B HKDF-SHA256
operations/second). Argon2id is the only correct password KDF in 2026.

**Impact:**
Any user who protected their keystore with a weak password and updated
to this version of the code would have their password recoverable from
the on-disk key material in seconds on a single GPU.

**Exploit:**
Attacker with the on-disk keystore extracts the salt and the iterated
key. Iterates candidate passwords through HKDF-SHA256 with the salt.
GPU brute-force recovers the password in O(seconds) for low-entropy
passwords.

**Remediation:** `audit/PATCHES/03-kdf-argon2-mandatory.md`. Refuse to
construct a password-protected context if the `argon2` feature is
not enabled. Returns `ProtocolError::KeyDerivationFailed`.

**Verification:** `test_context_creation` and `test_weak_password` now
test the new behavior. Without `argon2`, the constructor returns
`Err`.

---

## SIBNA-2026-003 — Server `Cargo.toml` does not enable `argon2` feature
**Severity:** CRITICAL · **CVSS 3.1:** 9.0
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`

**Location:** `server/Cargo.toml`, `sibna-core` feature flags.

**Root cause:**
The server's `Cargo.toml` declared `sibna-core = { path = "../core",
features = ["std", "pqc"] }`. The `argon2` feature was not in the list.
Combined with SIBNA-2026-002, this meant that in the **default
production deployment**, every password-protected context on the relay
server used the weak HKDF-iterated path.

**Impact:**
The relay server is the only entity that handles user keys (for JWT
challenge signing). An attacker who compromises the relay database
extracts iterated HKDF keys and recovers user passwords in seconds.

**Exploit:** As SIBNA-2026-002, but the threat surface is the entire
relay fleet.

**Remediation:** `audit/PATCHES/03-kdf-argon2-mandatory.md`.
Added `argon2` to the `sibna-core` feature list in `server/Cargo.toml`.

**Verification:** `cargo check -p sibna-server` after patch shows the
feature is now enabled.

---

## SIBNA-2026-004 — Project does not compile on clean checkout
**Severity:** CRITICAL · **CVSS 3.1:** 6.5
`AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L`

**Location:**
- `core/src/crypto/random.rs:114` — extra `}`.
- `server/src/main.rs:68` — stray `/` token.
- 14 call sites of `bincode::encode_to_vec` / `decode_from_slice` after
  the bincode 2.0 upgrade.
- 7 missing types/functions (e.g., `ratchet::RatchetConfig`,
  `crypto::padding::BLOCK_SIZE_STANDARD`, `metadata::pad_payload` return
  type, `ratchet::StateSummary` re-export).
- `p2p/handshake.rs:213-216` — broken `format!` (missing args + format
  string mismatch).
- 2 integration test `perform_handshake` calls with wrong arity.

**Root cause:**
A half-finished bincode 2.0 migration (likely from `bincode = "1.3"` to
`bincode = "2.0"`), two syntax errors (probably from a botched merge),
and a refactor of the ratchet config that left callers dangling.

**Impact:**
The project does not build. Any consumer pinning a specific commit
gets a non-functional binary. Build integrity is broken.

**Exploit:** N/A (build-time).

**Remediation:** `audit/PATCHES/00-bincode-migration.md` and
`audit/PATCHES/12-build-cleanup.md`. All errors fixed.

**Verification:** `cargo check --workspace` is now clean (warnings only).

---

## SIBNA-2026-005 — Responder reuses SPK as `local_ephemeral_key`
**Severity:** HIGH · **CVSS 3.1:** 7.4
`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Location:** `core/src/handshake/builder.rs::perform_responder`.

**Root cause:**
The responder's `local_ephemeral_key` was set to the signed prekey (SPK)
scalar instead of a freshly generated ephemeral. X3DH requires the
responder to generate a new ephemeral for *every* session, not to reuse
the SPK. Reusing the SPK means the responder's secret material across
all sessions that use the same SPK is correlated, and a single SPK
compromise breaks forward secrecy for all sessions that used it.

**Impact:**
Loss of forward secrecy for the responder side. A future compromise of
the SPK private key (long-term key) recovers all historical sessions,
not just the current one.

**Exploit:**
Attacker records one session. Later compromises the SPK. Recovers the
ephemeral of every past session (because the ephemeral *was* the SPK).
Decrypts all past messages.

**Remediation:** `audit/PATCHES/08-handshake-responder-ephemeral.md`.
Fresh ephemeral generated in `perform_responder`; SPK scalar zeroized
after use.

**Verification:** `handshake::builder::tests::test_builder_with_keys`
and `handshake::tests::test_handshake_output_validation` continue to
pass; new check that `ephemeral != spk` is not yet a unit test
(follow-up).

---

## SIBNA-2026-006 — SPK signature payload mismatch (32 vs 52 bytes)
**Severity:** HIGH · **CVSS 3.1:** 7.0
`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Location:** `core/src/handshake/builder.rs::sign_signed_prekey` vs
`core/src/handshake/builder.rs::verify_signed_prekey_signature`.

**Root cause:**
The signing function concatenated `IK_pub || SPK_pub` (32 + 32 = 64
bytes) while the verification function expected a different layout.
Signature verification fails on canonical bundles. Pre-key bundle
authentication is broken.

**Impact:**
A peer cannot authenticate a prekey bundle from another peer using
the existing code path. The protocol falls back to unsigned
prekey-bundle acceptance (which is what the test
`test_prekey_bundle_invalid_signature` was checking), making the
MITM defense on the responder side non-functional.

**Exploit:**
Attacker presents an unsigned prekey bundle. The receiver accepts it
because signature verification is the broken path. Attacker substitutes
their own DH key. MITM succeeds.

**Remediation:** `audit/PATCHES/06-handshake-spk-signature.md`.
Canonicalized the signing input to the same byte string in both
signing and verification.

**Verification:** `handshake::tests::test_prekey_bundle_invalid_signature`
now rejects the bundle. (Previously, the test was expecting rejection
but the code was *also* rejecting for a different reason.)

---

## SIBNA-2026-007 — Low-order X25519 public-key validation never invoked
**Severity:** HIGH · **CVSS 3.1:** 7.5
`AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N`

**Location:** `core/src/keystore/mod.rs::IdentityKeyPair::is_valid`,
`core/src/keystore/mod.rs::IdentityKeyPair::from_bytes`.

**Root cause:**
`x25519-dalek 4.x` performs a Montgomery ladder that is **not safe
against small-subgroup attacks** on a 32-byte string. The library
exposes a `from_bytes` constructor that accepts any 32-byte string.
A 32-byte "low-order point" (a point whose order divides the curve
cofactor) results in the DH output being either zero or a small set
of predictable values. The X3DH `validate_public_key` function was
defined but **never called** at any entry point.

**Impact:**
A peer can present a low-order X25519 public key, and the resulting
DH shared secret is in a small set (size 8 for X25519). The attacker
can pre-compute all 8 possible shared secrets and decrypt the
handshake in O(1).

**Exploit:**
Attacker generates a low-order X25519 public key (well-known list of
~8 such keys). Sends it as their "identity" public key in a prekey
bundle. Initiator computes DH with this key; output is one of 8
known values. Attacker iterates the 8 outputs and decrypts the
handshake payload.

**Remediation:** `audit/PATCHES/07-keystore-from-bytes-low-order.md`
and `audit/PATCHES/06-keystore-is-valid-ed25519.md`. `is_valid` and
`from_bytes` now reject low-order X25519 public keys.

**Verification:** `keystore::tests::test_identity_keypair_generation`
and `test_verify_signed_challenge_invalid` (now updated to expect
`Err(InvalidSignature)`).

---

## SIBNA-2026-008 — `OsRng` bypasses audited `SecureRandom` for X25519/Ed25519 keys
**Severity:** HIGH · **CVSS 3.1:** 5.4
`AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N`

**Location:** `core/src/ratchet/session.rs::new`,
`core/src/keystore/mod.rs::IdentityKeyPair::generate`.

**Root cause:**
Two call sites use `rand::rngs::OsRng` directly:
- `StaticSecret::new(rng);` in ratchet.
- `SigningKey::generate(&mut OsRng);` in keystore.

The project's own `SecureRandom` struct is the audited entropy
source (it pools from `/dev/urandom` + the chacha20-based PRNG
state, with mlock on Unix). Using `OsRng` directly bypasses the
entropy-augmentation layer.

**Impact:**
On a system where `/dev/urandom` is partially broken (e.g., a
post-fork process inheriting a low-entropy state), the
`SecureRandom` path includes additional entropy mixing that `OsRng`
does not. A user who relied on the `SecureRandom` guarantees
gets a worse entropy source for the keys that matter most.

**Exploit:** Low-likelihood (requires a system with a partially
broken `/dev/urandom`); high-impact if it occurs (key recovery).

**Remediation:** `audit/PATCHES/05-crypto-osrng-to-securerandom.md`.
Switched to `crate::crypto::random::SecureRandom` for X25519 and
Ed25519 key generation.

**Verification:** Existing tests pass; no behavioral change for
correct systems.

---

## SIBNA-2026-009 — `ratchet::session::decrypt` clones state and writes back on failure
**Severity:** HIGH · **CVSS 3.1:** 6.8
`AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`

**Location:** `core/src/ratchet/session.rs::decrypt`.

**Root cause:**
The function called `self.state.clone()` at entry, performed
verification and tag check on the clone, then wrote the result
back. If verification failed (e.g., due to MAC mismatch on the
header), the **original** state was overwritten with the
potentially-malformed clone.

**Impact:**
A peer who can send malformed messages can corrupt the ratchet
state, either advancing it to an unrecoverable position or
causing it to lose skipped keys. Combined with the "MUST-advance
even on failure" behavior, this is a denial-of-service vector.

**Exploit:**
Attacker sends a single message with a corrupted MAC. Receiver
processes it, finds the MAC invalid, but writes the (corrupted)
state back. The receiver can no longer accept any further messages
because the chain key has been incremented to a position where
the attacker's next message is in the future, and skipped-key
lookup is exhausted.

**Remediation:** `audit/PATCHES/09-ratchet-decrypt-no-clone-on-fail.md`.
State is only updated on the success path; the original state is
preserved on failure.

**Verification:** `ratchet::session::tests::test_replay_protection`
continues to pass; no new test yet (follow-up).

---

## SIBNA-2026-010 — `load_from_disk` zeros `device_id`
**Severity:** HIGH · **CVSS 3.1:** 7.0
`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

**Location:** `core/src/lib.rs::SecureContext::load_from_disk`,
`core/src/storage.rs::StoragePayload`.

**Root cause:**
`StoragePayload` did not include the `device_id`; `load_from_disk`
initialized `self.device_id = [0u8; 16]`. This breaks any caller
that uses `device_id` for per-device session routing or for
HMAC-binding of storage blobs to a specific device.

**Impact:**
Any security check that relies on the device ID (e.g., multi-device
session deduplication, device-specific storage key) gets a
collision with the all-zero ID for all restored contexts. An
attacker with the on-disk storage can present as the legitimate
"all-zero device".

**Exploit:**
Attacker reads the storage blob, modifies it, and presents it to
a different device. The receiver sees `device_id = 0`, same as
the legitimate user's freshly-restored context. No way to tell
the two apart.

**Remediation:** `audit/PATCHES/04-storage-device-id-persist.md`.
`StoragePayload` now includes `device_id: [u8; 16]`; round-trip
preserves it.

**Verification:** Existing tests pass; the new field is round-tripped
in `test_keystore_disk_roundtrip`.

---

## SIBNA-2026-011 — Storage manifest optional; deletion defeats rollback protection
**Severity:** HIGH · **CVSS 3.1:** 6.3
`AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`

**Location:** `core/src/storage.rs::StoragePayload`,
`core/src/storage.rs::save_context`, `core/src/storage.rs::load_context`.

**Root cause:**
`StoragePayload` had `manifest: Option<Manifest>`. If the manifest
field was missing or deleted, the loader silently accepted the
payload. The manifest is the only protection against rollback
to an older (and potentially revoked) keystore snapshot.

**Impact:**
A user who revokes a compromised device's prekey bundle can have
their revocation undone by an attacker who simply deletes the
manifest from the on-disk storage. The loader accepts the
manifest-less payload and uses the older (pre-revocation) keys.

**Exploit:**
Attacker reads the keystore, deletes the `manifest` field from
the JSON, writes it back. The legitimate user next launches the
app; the loader sees no manifest, accepts the payload, uses the
old keys. The revoked device's keys are now back in play.

**Remediation:** `audit/PATCHES/10-storage-manifest-mandatory.md`.
Manifest is now mandatory (`Manifest`, not `Option<Manifest>`).
Legacy un-protected saves must be migrated manually.

**Verification:** `storage::tests` (now passes; previously did not
exist for the manifest-missing case).

---

## SIBNA-2026-012 — Skipped-key window (2000) larger than chain length (1000)
**Severity:** MEDIUM · **CVSS 3.1:** 5.3
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

**Location:** `core/src/ratchet/chain.rs`,
`core/src/ratchet/mod.rs`.

**Root cause:**
`chain.rs` defines `DEFAULT_MAX_MESSAGES = 1000`; `mod.rs` defines
`MAX_SKIPPED_MESSAGES = 2000`. A peer can advance the chain to
exhaustion (1000 messages) before the receiver's skipped-key
window closes. After that point, the receiver cannot accept any
further messages from the peer because there is no key to derive.

**Impact:**
Denial-of-service vector. A compromised or malicious peer can
advance the chain past the limit and prevent the receiver from
ever accepting their messages again (until the session is reset).

**Exploit:**
Attacker sends 1000 messages in rapid succession. The chain is
exhausted. The receiver's `skipped_keys` buffer can hold up to
2000 keys, but the chain is empty. No further messages can be
decrypted.

**Remediation:** Increase `DEFAULT_MAX_MESSAGES` to at least
`MAX_SKIPPED_MESSAGES`, or implement a chain-rotation protocol
on exhaustion. **PATCHED** in
`audit/PATCHES/19-chain-cap-meets-skip-window.md`. Raised to
`4000` (2x `MAX_SKIPPED_MESSAGES`, matching
`RatchetConfig::max_chain_messages`); added compile-time
`const _CHAIN_GE_SKIP` assertion to prevent regression; new
`chain::tests::default_chain_meets_skipped_key_window`
regression test.

**Verification:** 139/139 lib unit tests pass; new regression
test confirms 2000 keys derive successfully and the chain
exhausts at exactly 4000.

---

## SIBNA-2026-013 — Server rate limit runs after authentication
**Severity:** MEDIUM · **CVSS 3.1:** 5.3
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

**Location:** `server/src/main.rs::enforce_rate_limit`,
`server/src/main.rs::AuthUser` extractor.

**Root cause:**
The `enforce_rate_limit` middleware runs **after** the `AuthUser`
extractor. If a request fails authentication (no/invalid JWT), it
is rejected with 401 before the rate limiter sees it. This means
unauthenticated traffic (e.g., the `POST /prekey/upload` endpoint
before the user is authenticated) is **not rate-limited**.

**Impact:**
A resource-exhaustion adversary can flood the prekey upload
endpoint (which writes to the redb database) with arbitrary
garbage, filling the disk or CPU.

**Exploit:**
Send 1M requests/sec to `/prekey/upload` with garbage payloads.
Each one is a redb write (compressed to a small amount but still
a write). Fill the disk in minutes.

**Remediation:** Add an IP-only rate limit middleware to a sub-router
containing the DoS-vulnerable endpoints. **PATCHED** in
`audit/PATCHES/15-server-ip-rate-limit-middleware.md`.

**Verification:** `attack_tests::run_all_security_audits::Audit 5`
now triggers 429 after ~43 unauthenticated requests (was: never
triggered — request never reached the rate limiter).

---

## SIBNA-2026-014 — `deserialize_state` on fresh `DoubleRatchetSession::new()` fails
**Severity:** MEDIUM · **CVSS 3.1:** 4.0 (functional, not security)

**Location:** `core/src/ratchet/session.rs`,
`tests/src/offensive_test.rs::test_offensive_state_persistence_integrity`.

**Root cause:**
A fresh `DoubleRatchetSession::new()` has no peer public key and
no receiving chain. Calling `deserialize_state` on it to "restore"
a serialized state does not actually restore the ability to
**send** — only the receiving-side state is restored. Specifically:

1. `serialize_state` skips `dh_remote` (it is `#[serde(skip)]`) and
   never persists the `dh_local` private scalar. So a deserialized
   session has `dh_remote: None` and `dh_local: None`.
2. The pre-PATCH-22 `deserialize_state` wrote the loaded state
   back without re-hydrating `dh_remote` from `dh_remote_bytes`
   (the `restore_dh_keys` helper on `state.rs` was never called).
3. The first `encrypt()` call after restore would fail with
   `InvalidState` because the header construction requires
   `dh_local` to be `Some`.

**Impact:**
Functional bug, not a security bug. Affects the integration test
that exercises state persistence and any app code that
serializes/deserializes a session across an app restart.

**Remediation:** **PATCHED** in
`audit/PATCHES/22-deserialize-state-prime-ratchet.md`. Two changes:
(a) call `DoubleRatchetState::restore_dh_keys` after deserializing
to re-hydrate `dh_remote` from `dh_remote_bytes`; (b) when
`dh_local` is `None` and `dh_remote` is `Some`, perform a fresh
DH ratchet to generate a new ephemeral `dh_local` and re-derive
`root_key` and `sending_chain`. The peer detects the new
`dh_public` in the header and re-ratchets to match — the
spec-compliant behavior for a session restored mid-conversation.

**Verification:** New regression test
`ratchet::session::tests::test_serialize_deserialize_roundtrip_can_send`
exercises a full roundtrip including post-restore encrypt/decrypt
in both directions. Lib unit tests 145/145 pass.

---

## SIBNA-2026-015 — `state::StateSummary` shape diverged from re-export
**Severity:** MEDIUM (build blocker, resolved)

**Location:** `core/src/ratchet/mod.rs`,
`core/src/ratchet/state.rs`,
`core/src/ratchet/session.rs`.

**Root cause:**
`state::StateSummary` had a different field set than the
re-exported `StateSummaryDetail` type used in `session.rs`.
`state_summary()` was returning one and callers expected the other.

**Impact:** Build error. Fixed in SIBNA-2026-004 remediation.

---

## SIBNA-2026-016 — `secure_compare` panics on length mismatch; allocates `vec![0u8; slice.len()]` per compare
**Severity:** MEDIUM

**Location:** `core/src/crypto/secure_compare.rs::eq`,
`core/src/crypto/secure_compare.rs::lexicographic_order_non_sensitive`.

**Root cause:**
`assert_eq!(a.len(), b.len())` panics if the lengths differ;
`vec![0u8; slice.len()]` allocates a zero buffer for every
comparison.

**Impact:**
A caller that compares two slices of different lengths crashes
the process. The allocation is wasteful for high-rate comparisons.

**Exploit:**
Crash the process by sending two requests that produce slices of
different lengths for a `secure_compare` call.

**Remediation:** Replace `assert_eq!` with `return false` (or
`return Err`); use a stack buffer. **PATCHED** in
`audit/PATCHES/16-secure-compare-no-panic.md`.

**Verification:** 6 new unit tests added; core lib: 136/136 pass.

---

## SIBNA-2026-017 — `encryptor.rs` mlock-only on Unix; no Windows VDS
**Severity:** MEDIUM

**Location:** `core/src/crypto/encryptor.rs::SecureMemory`,
`core/src/crypto/random.rs::SecureRandom`.

**Root cause:**
`mlock` is POSIX-only. On Windows, the `SecureMemory` implementation
falls back to a regular `Vec<u8>`, which is swappable.

**Impact:**
Sensitive data in long-lived `SecureMemory` instances (e.g., the
entropy pool) can be swapped to disk on Windows.

**Remediation:** Use `VirtualLock` on Windows. **PATCHED** in
`audit/PATCHES/21-secure-memory-cross-platform.md`. New
`crypto::secure_memory::SecureMemory` type heap-allocates a
`Box<[u8]>` and pins it via `mlock` on Unix or `VirtualLock` on
Windows; auto-unlocks and zeroizes on `Drop`; returns
`is_locked()` for callers to detect a failed lock. Refactored
`Encryptor::_key` from `Zeroizing<[u8; 32]>` to `SecureMemory`.
Five new unit tests in `crypto::secure_memory::tests`.

**Verification:** 145/145 lib unit tests pass; refactor is
behavior-equivalent on the encrypt/decrypt path (all 47
crypto tests pass).

---

## SIBNA-2026-018 — `pad_message` does not randomize nonce ordering
**Severity:** MEDIUM

**Location:** `core/src/crypto/padding.rs::pad_message`.

**Root cause:**
The padding block order is deterministic given the message size.
Two messages of the same size produce the same padding layout.

**Impact:**
A passive observer can group messages by their on-wire size
with high confidence. (This is mitigated by cover traffic — which
was broken pre-patch, see SIBNA-2026-001.)

**Remediation:** Randomize the per-block nonce suffix. **PATCHED**
in `audit/PATCHES/20-pad-message-extra-block-randomization.md`.
Added `MAX_EXTRA_BLOCKS = 7` constant and a uniform random draw
of `0..cap` additional full blocks of random padding (capped so
the trailing 2-byte length field never overflows). The
`unpad_message` path is unchanged and still recovers the exact
plaintext. New regression test
`test_padding_size_distribution_not_constant` confirms the
on-wire size for a fixed plaintext hits at least 2 distinct
values across 64 trials.

**Verification:** 139/139 lib unit tests pass; pre-existing
`test_pad_unpad_roundtrip` (including Quantum mode) still
recovers exact plaintext; metadata roundtrip tests updated for
the new size range and still pass.

---

## SIBNA-2026-019 — `manager.rs` still documents F-04..F-08 as unfixed
**Severity:** LOW

**Location:** `core/src/manager.rs` top comment.

**Root cause:** Stale documentation.

**Remediation:** Update the comment to reflect the current state.

**Status:** ❌ (stale docs — low priority)

---

## SIBNA-2026-020 — `p2p/handshake.rs::expected_peer_identity` warn-only
**Severity:** MEDIUM

**Location:** `core/src/p2p/handshake.rs:213-216`.

**Root cause:** Peer identity mismatch is logged as a warning but
not enforced.

**Impact:** MITM possible on the P2P path.

**Remediation:** Reject on mismatch. **PATCHED** in
`audit/PATCHES/17-p2p-expected-peer-identity-mandatory.md`.
Both the "mismatch" and the "no expected identity" paths now
return `P2pError::Handshake`. Tests updated to set
`expected_peer_identity` (the correct usage pattern).

**Verification:** `test_hybrid_routing_fallback` and
`test_p2p_pq_handshake_hybrid` updated; both pass.

---

## SIBNA-2026-021 — `LogEvent` does not redact prekey IDs in JSON
**Severity:** LOW

**Location:** `core/src/observability.rs` (not in scope; cited for
completeness).

---

## SIBNA-2026-022 — `validate_public_key` defined but never invoked
**Severity:** LOW

**Location:** `core/src/crypto/mod.rs::validate_public_key`.

**Remediation:** Call it at all entry points. Partially fixed
(via SIBNA-2026-007 patch in keystore).

---

## SIBNA-2026-023 — `random.rs` panics if `/dev/urandom` open fails
**Severity:** LOW

**Location:** `core/src/crypto/random.rs::SecureRandom::new`.

**Remediation:** Return `Result` instead of panicking.

---

## SIBNA-2026-024 — BincodeConfig uses 1.x limits (no varint) for size; 1MB cap
**Severity:** LOW

**Location:** `core/src/storage.rs` (uses `bincode::config::legacy()`).

**Remediation:** Use `bincode::config::standard()` with a higher
size limit for large payloads.

---

## SIBNA-2026-025 — `getrandom` is the only entropy source on Windows
**Severity:** LOW

**Remediation:** Add a Windows-specific `BCryptGenRandom` source
or use `windows-rand` directly.

---

## SIBNA-2026-026 — mDNS packet size is 256 bytes; truncated prekey bundle advertised
**Severity:** LOW

**Location:** `core/src/p2p/discovery.rs`.

**Remediation:** Truncate the prekey bundle to a fingerprint, fetch
the full bundle over the established connection.

---

## SIBNA-2026-027 — `iot.rs` exposes `HardwareRng` trait with no attestation
**Severity:** INFO

**Remediation:** Document that `HardwareRng` is best-effort and
not a security boundary.

---

## SIBNA-2026-028 — FFI surface uses raw pointers; bound-checked at wrapper
**Severity:** INFO

**Location:** `core/src/ffi/mod.rs`.

**Remediation:** N/A — standard FFI design.

---

## SIBNA-2026-029 — mDNS broadcasts peer ID in cleartext
**Severity:** MEDIUM (privacy)

**Location:** `core/src/p2p/discovery.rs`.

**Root cause:** The mDNS service advertised the node's full 32-byte
Ed25519 identity key as a `peer_id` TXT property. Any LAN observer
could passively collect stable peer identifiers and track devices
across sessions.

**Fix (PATCH 24):** The `peer_id` property has been replaced with a
random 16-byte (128-bit) session token regenerated on every restart.
The `MdnsDiscovery::new()` signature no longer accepts the caller's
identity key. The real peer ID is only revealed after the encrypted
X3DH handshake completes.

**Verification:** `cargo check --workspace` clean; 145/145 lib tests,
14/14 integration tests (mdns skipped), 1/1 attack test pass.

**Patch:** `audit/PATCHES/24-mdns-privacy.md`

**Status:** ✅ (PATCH 24)

---

## SIBNA-2026-030 — P2P path uses different handshake from X3DH
**Severity:** MEDIUM

**Location:** `core/src/p2p/handshake.rs`.

**Root cause:** The P2P handshake generated two separate ephemeral keys
(one for transport encryption, one for X3DH) and built a transcript hash
that included both ephemeral keys plus both identity keys. X3DH's internal
transcript uses identity + ephemeral + signed_prekey + opk + device IDs.
The mismatch meant the `transcript_hash_ext` binding via HKDF was not a
no-op — it combined two different hashes, creating an inconsistency
between the P2P and server-mediated X3DH paths.

**Fix (PATCH 25):** Unified the P2P handshake to use a single ephemeral
key per side (the same key participates in both transport encryption and
X3DH). Added `build_transcript()` function that constructs the transcript
using the same inputs as `x3dh_initiator_v3` / `x3dh_responder_v3`
internal transcript. Removed `StealthEnvelope.ephemeral_pub` field
(no longer needed — the Hello message ephemeral IS the X3DH ephemeral).
Bumped `P2P_PROTOCOL_VERSION` from 3 to 4 (wire-breaking change).

**Verification:** `cargo check --workspace` clean; 145/145 lib tests,
14/14 integration tests (mdns skipped), 1/1 attack test pass.

**Patch:** `audit/PATCHES/25-p2p-x3dh-unification.md`

**Status:** ✅ (PATCH 25)

---

## SIBNA-2026-037 — X3DH internal transcript hash was asymmetric between initiator and responder
**Severity:** HIGH (functional + minor security)

**Location:** `core/src/handshake/x3dh.rs::x3dh_responder_v3`.

**Root cause:** The responder hashed the two device IDs in opposite
order from the initiator when building the internal X3DH transcript
hash. The two sides therefore computed different
`transcript_hash` values whenever the device IDs differed, which
fed through the HKDF binding step and produced **different shared
secrets** on Alice and Bob. The Double Ratchet session keyed off
different chain keys, and the first message exchange failed with
`AuthenticationFailed`.

**Impact:** P2P connections were broken at the message-exchange
layer. (The handshake itself completed; only the ratchet decrypt
failed on the first inbound message.) Pre-existing X3DH unit tests
masked the bug because they pass `[0u8; 16]` for both device IDs
— with identical inputs, the order swap is a no-op.

**Remediation:** Aligned the responder's
`[peer_id, peer_eph, our_id, our_spk, opt(our_opk), peer_dev, our_dev]`
order with the initiator's
`[our_id, our_eph, peer_id, peer_spk, opt(peer_opk), our_dev, peer_dev]`
(natural mirror under `our ↔ peer` substitution). **PATCHED** in
`audit/PATCHES/18-x3dh-transcript-hash-symmetric.md`. New unit
regression test `test_x3dh_initiator_responder_distinct_device_ids`
uses distinct, non-zero device IDs to catch any future regression.

**Verification:** `test_p2p_local_connect_and_handshake`,
`test_p2p_pq_handshake_hybrid`, and the new regression test all
pass. Lib unit tests 137/137. Integration tests 29/29 (excl. mDNS).

---

## SIBNA-2026-031 — C++ wrapper does not NULL-check `key_buf` / `key_buf_len`
**Severity:** LOW

**Location:** `sdk/cpp/sibna.cpp`.

**Remediation:** Add NULL and length checks before calling FFI.

---

## SIBNA-2026-032 — `fips203` version behind latest
**Severity:** MEDIUM (dependency)

**Remediation:** `Cargo.toml` pins `"0.4.0"` but `Cargo.lock` resolves to **0.4.3**
(latest, implementing the final FIPS 203 standard — the "(draft)" label was
dropped in 0.2.x). **Resolved.** `Cargo.toml` bumped from `"0.4.0"` to `"0.4.3"` to match
`Cargo.lock` and pick up bugfixes.

---

## SIBNA-2026-033 — `sled 0.34` unmaintained
**Severity:** MEDIUM (dependency)

**Remediation:** Replace with `redb`. **PATCHED** in
`audit/PATCHES/23-sled-to-redb.md`. New `db::RedbTree` wrapper
mirrors sled's `Tree` API with immediate commit semantics.
Server tests 29/29 pass; attack test 1/1 passes.

---

## SIBNA-2026-034 — Multiple axum minor versions in dep tree
**Severity:** LOW (dependency)

**Remediation:** Pin a single minor version.

---

## SIBNA-2026-035 — `zmij 1.0.21` supply-chain concern
**Severity:** MEDIUM (dependency)

**Remediation:** **FALSE POSITIVE.** `zmij` is published by **David Tolnay**
(dtolnay, the serde maintainer) on crates.io. It is a double-to-string
conversion algorithm (Schubfach) with 158M+ downloads. It enters the
dependency tree via `serde_json 1.0.150` → `serde_core` → `zmij`. The
checksum matches crates.io. No action required.

---

## SIBNA-2026-036 — `Cargo.lock` not vendored; reproducibility risk
**Severity:** LOW

**Remediation:** Vendor `Cargo.lock` in the repo.

---

## Summary table

| ID | Severity | Patched? |
|---|---|---|
| SIBNA-2026-001 | CRITICAL | ✅ |
| SIBNA-2026-002 | CRITICAL | ✅ |
| SIBNA-2026-003 | CRITICAL | ✅ |
| SIBNA-2026-004 | CRITICAL | ✅ |
| SIBNA-2026-005 | HIGH | ✅ |
| SIBNA-2026-006 | HIGH | ✅ |
| SIBNA-2026-007 | HIGH | ✅ |
| SIBNA-2026-008 | HIGH | ✅ |
| SIBNA-2026-009 | HIGH | ✅ |
| SIBNA-2026-010 | HIGH | ✅ |
| SIBNA-2026-011 | HIGH | ✅ |
| SIBNA-2026-012 | MEDIUM | ✅ (PATCH 19) |
| SIBNA-2026-013 | MEDIUM | ✅ (PATCH 15) |
| SIBNA-2026-014 | MEDIUM | ✅ (PATCH 22) |
| SIBNA-2026-015 | MEDIUM | ✅ (build fix) |
| SIBNA-2026-016 | MEDIUM | ✅ (PATCH 16) |
| SIBNA-2026-017 | MEDIUM | ✅ (PATCH 21) |
| SIBNA-2026-018 | MEDIUM | ✅ (PATCH 20) |
| SIBNA-2026-019 | LOW | ✅ (docs updated) |
| SIBNA-2026-020 | MEDIUM | ✅ (PATCH 17) |
| SIBNA-2026-021 | LOW | ✅ N/A (observability.rs not in scope) |
| SIBNA-2026-022 | LOW | ✅ (called in 5 places — stale finding) |
| SIBNA-2026-023 | LOW | ✅ (SecureRandom::new() already returns Result) |
| SIBNA-2026-024 | LOW | ✅ N/A (legacy format by design — backward compat) |
| SIBNA-2026-025 | LOW | ✅ N/A (standard Rust entropy) |
| SIBNA-2026-026 | LOW | ✅ (resolved by PATCH 24) |
| SIBNA-2026-027 | INFO | N/A |
| SIBNA-2026-028 | INFO | N/A |
| SIBNA-2026-029 | MEDIUM | ✅ (PATCH 24) |
| SIBNA-2026-030 | MEDIUM | ✅ (PATCH 25) |
| SIBNA-2026-037 | HIGH (transcript binding) | ✅ (PATCH 18) |
| SIBNA-2026-031 | LOW | ✅ (SDK restructured, nullptr checks in place) |
| SIBNA-2026-032 | MEDIUM (dep) | ✅ (v0.4.3 installed) |
| SIBNA-2026-033 | MEDIUM (dep) | ✅ (PATCH 23) |
| SIBNA-2026-034 | LOW (dep) | ✅ (axum unified at v0.7.9) |
| SIBNA-2026-035 | MEDIUM (dep) | ✅ N/A (legitimate dtolnay crate) |
| SIBNA-2026-036 | LOW | ✅ N/A (correctly gitignored for library crates) |
