# Patch 16 — `secure_compare` no longer panics on length mismatch (SIBNA-2026-016)
**Finding:** SIBNA-2026-016 (panic in constant-time compare)
**File:** `core/src/crypto/secure_compare.rs`
**Date:** June 2026

## Problem
Three functions in `core/src/crypto/secure_compare.rs` panicked on
edge cases:

- `constant_time_copy` — `assert_eq!(dst.len(), src.len())` panicked if
  the caller passed mismatched buffer lengths. In a long-running
  process serving requests, a single bad call would crash the process
  and leak the timing oracle the function was supposed to prevent.
- `constant_time_is_zero` — allocated a `vec![0u8; slice.len()]` per
  call. Wasteful, and a DoS amplifier if called in a tight loop with
  attacker-controlled slice length.
- `secure_password_compare` and `batch_constant_time_compare` —
  `subtle::ConstantTimeEq::ct_eq` panics on length mismatch. The
  previous code did not guard against this.

## Fix
- `constant_time_eq` — explicit length check, returns `false` on
  mismatch (no panic).
- `constant_time_copy` — returns `false` on length mismatch; the
  destination buffer is left untouched.
- `constant_time_is_zero` — replaced the per-call zero buffer
  allocation with a constant-time AND of `byte.ct_eq(&0u8)` across
  all bytes.
- `secure_password_compare` — explicit length check before the
  `ct_eq` call.
- `batch_constant_time_compare` — per-candidate length check.

## Tests
Added 6 new unit tests to exercise the fixed paths:
```rust
#[test] fn eq_length_mismatch_no_panic() { ... }
#[test] fn password_compare_length_mismatch() { ... }
#[test] fn constant_time_copy_length_mismatch() { ... }
#[test] fn constant_time_copy_works() { ... }
#[test] fn is_zero_no_alloc() { ... }
#[test] fn batch_compare_length_mismatch() { ... }
```

## Verification
`cargo test --lib -p sibna-core`:
- Pre-patch: 130 tests, all pass.
- Post-patch: 136 tests, all pass (130 + 6 new).

## Notes
The fix preserves constant-time behavior for equal-length inputs.
For length-mismatched inputs, the function returns early — this is
acceptable because the *result* (false / no-op) is independent of
the input values, and the timing difference is at most the time to
compare the length fields (O(1)).

A more aggressive constant-time fix would mask the comparison result
with a length-mismatch flag, but the marginal security benefit does
not justify the added complexity for these helpers, which are not
used in timing-sensitive code paths (the ratchet's MAC verification
uses `chacha20poly1305`'s built-in constant-time tag check).
