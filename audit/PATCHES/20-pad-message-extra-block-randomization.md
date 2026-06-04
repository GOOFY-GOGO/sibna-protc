# Patch 20 — Randomize per-block padding suffix (SIBNA-2026-018)
**Finding:** SIBNA-2026-018 (pad_message nonce ordering is deterministic)
**File:** `core/src/crypto/padding.rs`
**Date:** June 2026

## Problem

`pad_message` already had two layers of randomness — random
`prefix_len` (1-8 bytes) and random padding bytes — but the
**padded on-wire length** was a deterministic function of the
plaintext length and the block size. Two messages with the same
plaintext length always produced the same on-wire length (modulo
the prefix_len's small effect on whether the boundary was crossed).

This let a passive observer group messages by their on-wire size
with high confidence. Combined with a known traffic pattern (e.g.
heartbeat every 60s, or a chat app that pads to 1024B), this is
a metadata leak.

## Fix

Added a third layer of randomness: the per-call draw of
`0..MAX_EXTRA_BLOCKS` additional full blocks of random padding
(default cap: 7). The total on-wire size for a given plaintext
length can now be one of 8 distinct values (the minimum-boundary
size plus 0..7 extra full blocks).

The actual `pad_len` is encoded in the existing trailing 2-byte
LE field, so `unpad_message` continues to recover the exact
plaintext without modification.

The draw is **bounded** so the final `pad_len` never exceeds
`MAX_PADDING_BYTES` (65535) — important for `Quantum` mode (block
size 65536) where one extra block would push us over the cap.

```diff
+/// SIBNA-2026-018 (PATCH 20): maximum number of *additional* full blocks
+/// of random padding that may be appended on top of the minimum needed
+/// to reach the next block boundary. With `MAX_EXTRA_BLOCKS = 7`, the
+/// on-wire size of a given plaintext can occupy any of 8 distinct
+/// padded sizes (the minimum-boundary size plus 0..7 extra blocks).
+///
+/// Chosen to keep the worst-case bandwidth overhead bounded (7 extra
+/// blocks at the largest Quantum mode = 7 × 64 KiB = 448 KiB per
+/// message) while still defeating simple per-size traffic analysis.
+pub const MAX_EXTRA_BLOCKS: usize = 7;

-pub fn pad_message(plaintext: &[u8], mode: PaddingMode) -> ProtocolResult<Vec<u8>> {
+pub fn pad_message(plaintext: &[u8], mode: PaddingMode) -> ProtocolResult<Vec<u8>> {
     …
-    let remainder = min_total % block;
-    let pad_len = if remainder == 0 { 0 } else { block - remainder };
+    let remainder = min_total % block;
+    let min_pad_len = if remainder == 0 { 0 } else { block - remainder };
+
+    // SIBNA-2026-018: randomize the per-block suffix length so two
+    // messages of the same plaintext length don't necessarily produce
+    // the same on-wire size. We add 0..MAX_EXTRA_BLOCKS additional
+    // full blocks of random padding, but cap the random draw so the
+    // final pad_len always fits in the 2-byte length field and never
+    // exceeds MAX_PADDING_BYTES.
+    let max_blocks_for_budget = MAX_PADDING_BYTES.saturating_sub(min_pad_len) / block;
+    let cap = max_blocks_for_budget.min(MAX_EXTRA_BLOCKS);
+    let extra_blocks = (rng.next_u32() % (cap as u32 + 1)) as usize;
+    let pad_len = min_pad_len + extra_blocks * block;
```

## Test updates

### Existing tests relaxed (no longer assert exact padded size)

`crypto::padding::tests::test_padding_hides_size` and
`metadata::tests::test_padding_roundtrip_small` /
`test_padding_roundtrip_large` /
`test_padding_size_indistinguishable` previously asserted exact
on-wire sizes (`1024` or `2 * 1024`). Updated to assert the new
invariant: the padded size is in the range
`[block_size, 8 * block_size]` and is a multiple of `block_size`,
and `unpad_*` still recovers the exact plaintext.

### New regression test
`crypto::padding::tests::test_padding_size_distribution_not_constant`

Pads a fixed 22-byte plaintext 64 times with `PaddingMode::Standard`
and asserts the resulting set of padded sizes contains **at least 2
distinct values**. With 8 possible sizes and 64 trials, the
probability of all 64 picking the same size by chance is
`(1/8)^63 ≈ 10^{-57}`, so this is a near-deterministic check that
the randomization is in effect.

## Verification

| Suite | Pre-patch | Post-patch |
|---|---:|---:|
| `core` lib unit tests | 137/137 | **139/139** ✅ |
| `attack_tests::run_all_security_audits` | 12/12 | **12/12** ✅ |
| `multi_device_tests` | 3/3 | **3/3** ✅ |
| `integration_tests` (excl. mDNS) | 29/29 | **29/29** ✅ |
| `cargo check --workspace` | 0 errors | **0 errors** ✅ |

Specifically:
- `crypto::padding::tests::test_pad_unpad_roundtrip` — **PASS**
  (Quantum mode case still recovers exact plaintext).
- `crypto::padding::tests::test_padding_size_distribution_not_constant` (NEW) — **PASS**.
- `metadata::tests::test_padding_roundtrip_large` — **PASS**
  (now asserts size range `[2*B, 9*B]`).
- `metadata::tests::test_padding_size_indistinguishable` — **PASS**
  (now asserts size range, not exact equality).

## Out-of-scope follow-ups

- **Cover-traffic alignment** (SIBNA-2026-001 area): cover
  messages should also pick from this distribution so an observer
  cannot distinguish cover from real by size.
- **Cross-block size modes**: a more advanced scheme could let
  the caller choose the random-draw distribution (e.g., uniform
  in `[0, 2^k)` for k ∈ {0..7}) to trade off overhead vs.
  indistinguishability. The current `0..8` uniform distribution
  is the right default.
- **Padding oracle attacks**: the 2-byte LE length field is part
  of the AEAD plaintext (encrypted), so a padding oracle is not
  directly possible. However, an attacker who can submit chosen
  plaintexts and observe their encrypted size can still infer
  the plaintext size modulo the block size. This is a
  fundamental limitation of size-hiding schemes; cover traffic
  is the only complete mitigation.
