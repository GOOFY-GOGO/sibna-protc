# Patch 19 — Chain-key cap raised to match skipped-key window (SIBNA-2026-012)
**Finding:** SIBNA-2026-012 (chain length < skipped-key window)
**File:** `core/src/ratchet/chain.rs`
**Date:** June 2026

## Problem

`ChainKey::DEFAULT_MAX_MESSAGES = 1000` was smaller than
`ratchet::MAX_SKIPPED_MESSAGES = 2000`. A compromised or malicious
peer could send 1000 messages in rapid succession and exhaust the
chain. After exhaustion the chain would refuse to produce any more
message keys (`next_message_key()` returns `None`), and the receiver
could no longer accept any further messages — even though the
receiver's `skipped_keys` buffer was supposed to have room for
2000 keys.

This is a denial-of-service vector: a single burst of `1001`
messages permanently breaks the session until reset.

## Fix

Raised `ChainKey::DEFAULT_MAX_MESSAGES` from `1000` to `4000` (2x
`MAX_SKIPPED_MESSAGES`, matching the existing
`RatchetConfig::max_chain_messages` value that PATCH 00 had already
set). Added a compile-time `const _CHAIN_GE_SKIP: ()` assertion so
any future refactor that shrinks the default fails the build.

```diff
-    pub const DEFAULT_MAX_MESSAGES: u64 = 1000;
+    pub const DEFAULT_MAX_MESSAGES: u64 = 4000;
+
+    // Compile-time guard: the default must never drop below the skipped-key
+    // window. If a future refactor shrinks this, the build fails.
+    const _CHAIN_GE_SKIP: () = assert!(
+        Self::DEFAULT_MAX_MESSAGES as usize >= super::MAX_SKIPPED_MESSAGES,
+        "ChainKey::DEFAULT_MAX_MESSAGES must be >= MAX_SKIPPED_MESSAGES \
+         (SIBNA-2026-012): chain exhaustion otherwise breaks decrypt after \
+         skipped-key window closes."
+    );
```

## Test

Added `chain::tests::default_chain_meets_skipped_key_window`:

1. Asserts `DEFAULT_MAX_MESSAGES as usize >= MAX_SKIPPED_MESSAGES`
   (mirrors the compile-time guard at runtime).
2. Derives exactly `MAX_SKIPPED_MESSAGES` (2000) keys and asserts
   each one succeeds — this is the SIBNA-2026-012 invariant.
3. Derives 16 more keys and confirms headroom past the skipped-key
   window.
4. Exhausts the chain to `DEFAULT_MAX_MESSAGES` (4000) and confirms
   `next_message_key()` returns `None` at exactly that index.

## Verification

| Suite | Pre-patch | Post-patch |
|---|---:|---:|
| `core` lib unit tests | 137/137 | **139/139** ✅ (+1 chain, +1 size-distribution from PATCH 20) |
| `attack_tests::run_all_security_audits` | 12/12 | **12/12** ✅ |
| `multi_device_tests` | 3/3 | **3/3** ✅ |
| `integration_tests` (excl. mDNS) | 29/29 | **29/29** ✅ |
| `cargo check --workspace` | 0 errors | **0 errors** ✅ |

## Related findings (out of scope)

This patch closes the immediate DoS, but two long-term
improvements remain:

- **Chain rotation on exhaustion**: when `needs_rotation()` is
  true the ratchet currently rotates by deriving a new
  `sending_chain` from the same `root_key` (via `perform_dh_ratchet`).
  This is a "soft rotation" — an attacker who can force rotation
  repeatedly could deplete the root key's entropy. A future
  patch could require a fresh DH ratchet (initiator → responder)
  on rotation.
- **Adaptive cap based on traffic shape**: the fixed cap
  `4000` is conservative for batch messaging but wasteful for
  long-lived low-volume sessions. A future patch could
  parameterize this on `RatchetConfig` (already present in
  PATCH 00) and surface it as a per-session tuning knob.
