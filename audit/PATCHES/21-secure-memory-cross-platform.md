# Patch 21 — Cross-platform SecureMemory with mlock / VirtualLock (SIBNA-2026-017)
**Finding:** SIBNA-2026-017 (mlock-only on Unix; no Windows VDS)
**Files:** `core/src/crypto/secure_memory.rs` (new),
`core/src/crypto/encryptor.rs` (refactor),
`core/src/crypto/mod.rs` (module registration)
**Date:** June 2026

## Problem

Long-lived sensitive buffers in the crypto stack (notably the
per-Encryptor 32-byte key) were stored in `Zeroizing<[u8; 32]>`
on the stack/inline in the struct. On Unix, `SecureRandom::entropy_pool`
was the only buffer pinned against swapping (via `libc::mlock`).
On Windows, the entropy pool was already pinned via `VirtualLock`,
but **every other** long-lived key was not pinned on either
platform.

Without pinning, the OS is free to swap the page containing the
key to disk, where it can be recovered by an attacker with
post-exploitation access to the swap file, the hibernation file,
or a memory-dump primitive that scans the page file.

## Fix

Introduced `core/src/crypto/secure_memory.rs` — a `SecureMemory`
type that:

1. Heap-allocates a `Box<[u8]>` (stable address for the lifetime
   of the struct).
2. On Unix: calls `libc::mlock` to pin the pages in physical RAM.
3. On Windows: calls `VirtualLock` (via `windows_sys::Win32::System::Memory`)
   to pin the pages.
4. On other platforms: no-op + `tracing::warn!` (best effort).
5. On `Drop`: unlocks the pages (so the kernel can reclaim them
   after process exit) and zeroizes the bytes.
6. Returns `is_locked()` so callers can detect a failed
   `mlock`/`VirtualLock` (e.g., due to `RLIMIT_MEMLOCK` on Unix).

`Encryptor::_key` is now a `SecureMemory` instead of a
`Zeroizing<[u8; 32]>`.

### Notes / limitations

- `mlock` on Unix is subject to `RLIMIT_MEMLOCK`. If the limit is
  too small, `mlock` returns `ENOMEM` and the buffer is left
  **unlocked** (logged via `tracing::warn`). Callers must treat
  the buffer as best-effort secure, not as a hard guarantee.
  This is documented in the type's rustdoc.
- Locking is a no-op for `size == 0` buffers.
- `SecureMemory` is `!Clone` to make accidental duplication hard,
  and implements `Send + Sync` (the underlying `Box<[u8]>` is
  already `Sync`).
- `Debug` redacts the bytes (only `len` and `locked` are shown) so
  accidental `dbg!()` doesn't leak the key to logs.

## Tests

Five new unit tests in `crypto::secure_memory::tests`:

| Test | Asserts |
|---|---|
| `basic_allocation_and_access` | 64-byte buffer, zero-initialized, write/read round-trips |
| `from_bytes_initializes` | `from_bytes(payload)` copies exactly |
| `zero_sized_buffer_is_safe` | `new(0)` doesn't panic; `drop` skips empty buffer |
| `drop_does_not_panic` | 16 construct/drop cycles (regression for double-unlock) |
| `debug_redacts_contents` | `format!("{:?}", buf)` does NOT contain the secret bytes |

## Verification

| Suite | Pre-patch | Post-patch |
|---|---:|---:|
| `core` lib unit tests | 139/139 | **145/145** ✅ (+5 SecureMemory, +1 roundtrip from PATCH 22) |
| `attack_tests::run_all_security_audits` | 12/12 | **12/12** ✅ |
| `multi_device_tests` | 3/3 | **3/3** ✅ |
| `integration_tests` (excl. mDNS) | 29/29 | **29/29** ✅ |
| `cargo check --workspace` | 0 errors | **0 errors** ✅ |

## Out-of-scope follow-ups

- **Audit other long-lived keys** in the codebase: `ChainKey.key`,
  `IdentityKeyPair.x25519_secret`, and the ratchet state
  `dh_local` (when in memory) all live on the heap and would
  benefit from `SecureMemory` wrapping. A future patch could
  systematically refactor these.
- **Set `process::ExitCode` or signal handling to flush keys on
  controlled shutdown** — a `Drop` on `SecureMemory` will
  unlock and zeroize, but only when the owning `SecureContext`
  is dropped, not on signal. A signal handler that triggers
  an orderly teardown is a defense-in-depth measure.
- **Cross-platform mlock policy** — on Linux, `mlock` does not
  count against `RLIMIT_MEMLOCK` for the root user, but does for
  unprivileged users. A deployment guide entry could document
  the recommended `ulimit -l` setting.
