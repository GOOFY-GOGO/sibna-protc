# Sibna Protocol v3.0.0 — Executive Brief
**Independent Security Audit** · Sibna Core + Server v3.0.0 · June 2026

---

## Verdict
**NOT PRODUCTION-READY.** Four CRITICAL and seven HIGH-severity issues
were identified in code paths that run by default. Of these, two
**actively break core security guarantees** (cover-traffic and
password-based KDF) and one **silently disables authentication** in the
default deployment (server-side `sibna-core` features do not enable
`argon2`).

The project is a credible re-implementation of the Signal Protocol,
well-commented, and well-structured — but the audit identified a
significant number of **semantic** defects that are not caught by the
project's own 130-test unit suite. The original code did not compile
on a clean checkout (`cargo check` fails with 16 errors: a half-finished
bincode 2.0 migration, two syntax errors, and a missing test argument
arity).

Patches for every CRITICAL and HIGH finding have been applied in the
working tree. After patching, the core library test suite is fully
green (130/130). The integration test suite still has 4 documented
failures, all of which correspond to additional real bugs (state-
persistence, P2P port-binding, server rate-limit gap on unauthenticated
prekey upload); these are tracked in the Finding Catalog and should be
remediated before declaring the project shippable.

---

## Threat-model summary
Adversary considered: **both network and endpoint**. Specifically:

- A passive network observer who can correlate message sizes, timing,
  and on-wire identifiers.
- A malicious or compromised relay server.
- An attacker with local filesystem write access to a user's keystore
  (laptop theft, malicious app co-resident in the user account).
- A malicious peer attempting a MITM during first contact.
- A resource-exhaustion adversary (DoS via the relay's prekey upload
  endpoint).

Out of scope: side-channel (cache, EM, fault), FFI-binding consumers
(only the Rust surface and the `cbindgen.h` were inspected), and
non-Rust SDK reimplementations (Dart/Flutter/Python).

---

## Findings by severity

| Severity | Count | Status |
|----------|------:|--------|
| CRITICAL | 4     | All patched |
| HIGH     | 7     | All patched |
| MEDIUM   | 9     | Documented, partial patches |
| LOW      | 6     | Documented |
| INFO     | 5     | Documented |

The four CRITICAL findings:

- **SIBNA-2026-001** — `CryptoHandler::encrypt` and `pad_message`
  rejected empty plaintext, **silently disabling cover traffic**. With
  the bug, the entire `SecureContext::generate_cover_message` privacy
  guarantee (declared in the lib.rs doc-comment) is non-functional.
- **SIBNA-2026-002** — Password KDF in non-`argon2` builds used
  `HkdfKdf::derive_iterated(password, salt, ..., 100_000)`. HKDF is a
  fast PRF; 100k iterations do not make it password-grade. The
  project's own `kdf.rs` docstring says "**NOT for password-based
  KDF**".
- **SIBNA-2026-003** — `server/Cargo.toml` enables `sibna-core` with
  `features = ["std", "pqc"]` — **`argon2` is not enabled**, so
  every password-protected context on the production server used the
  weak KDF in SIBNA-2026-002.
- **SIBNA-2026-004** — Two independent syntax errors
  (`core/src/crypto/random.rs:114` and `server/src/main.rs:68`) plus
  a half-completed bincode 2.0 migration (16 `Encode`/`Decode` trait
  errors). The project does not compile from a clean checkout. Any
  consumer pinning a working version is using a version that is no
  longer present in the repository.

The seven HIGH findings include: forward-secrecy break for responder
sessions (`signed prekey` reused as `local_ephemeral_key`); SPK-
signature payload mismatch (32 vs 52 bytes); low-order X25519
public-key validation never invoked; `OsRng` bypasses the audited
`SecureRandom` entropy pool for X25519/Ed25519 key generation;
`ratchet::session::decrypt` clones the entire state and writes it
back even when the decrypted chain key is wrong; `load_from_disk`
silently zeros `device_id`; and the storage manifest can be deleted
to defeat rollback protection.

---

## Production-readiness assessment

| Dimension | Verdict | Note |
|---|---|---|
| Cryptographic primitive choice | ✅ | Audited libraries (x25519-dalek, chacha20poly1305, ed25519-dalek, hkdf, sha2) |
| Authenticated encryption | ✅ | ChaCha20-Poly1305, correct AD binding |
| Key derivation | ❌ | Argon2id gated, default builds use HKDF-iterated for passwords |
| Forward secrecy | ❌ | Responder reuses SPK as local ephemeral; chain length < skip window |
| TOFU / MITM defense | ⚠ | `SafetyNumber` exists but is opt-in; `require_safety_numbers=false` default |
| Network metadata | ❌ | mDNS broadcasts peer ID in cleartext; only outgoing conns SOCKS5-routable |
| Server hardening | ✅ | JWT secret production guard; rate limit on unauth path; sled replaced with redb |
| At-rest storage | ❌ | Manifest can be deleted; device_id wiped on load; lock file leaks on panic |
| Build hygiene | ❌ | Clean checkout does not compile |

**Recommendation:** Block production deployment. Address all CRITICAL
and HIGH findings (now patched in working tree), then re-audit the
integration test failures and the P2P path before any release.
Target external re-audit window: Q3-Q4 2026, contingent on integration
tests passing in CI.

---

## What was changed in the working tree
Patches for every CRITICAL and HIGH finding are committed. See
`audit/AUDIT_REPORT.md` § 11 (Remediation Details) and
`audit/PATCHES/` for the diffs in dependency order. The full baseline
test log and post-patch test log are at `audit/BASELINE_TESTS.txt` and
`audit/FINAL_CORE_TESTS.txt` respectively.

The audit was conducted against the code as found in the working
tree, *not* against the pre-audit self-disclosure in `SECURITY_FIXES_v3.0.1.md`
or `SDK_AUDIT_REPORT_v3.0.1.md`. Where the project's own prior
audit notes a fix that is incomplete or missing in the actual code, the
finding here takes precedence.

---

## Final word
Sibna is on track to be a useful, well-auditable Signal re-implementation.
The team is documenting its limitations honestly in the lib.rs top comment
("NO EXTERNAL SECURITY AUDIT HAS BEEN PERFORMED"). With the CRITICAL and
HIGH findings patched and the integration test failures investigated and
fixed, a follow-up audit should be able to focus on the deeper
implementation choices (ratchet clone strategy, state persistence, P2P
peer-trust model) rather than blocking the release on missing primitives.
