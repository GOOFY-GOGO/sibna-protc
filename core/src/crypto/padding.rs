//! Message padding for metadata protection.
//!
//! This module provides functions to pad and unpad messages to fixed block sizes,
//! mitigating message size leakage to network observers.
//!
//! ## V3.1.0 Hardening
//! In "Fortress" mode, we add a random prefix (1-8 bytes) and move the length field 
//! to the encrypted boundary to prevent range inference attacks.

use crate::error::{ProtocolError, ProtocolResult};
use crate::crypto::random::SecureRandom;
use serde::{Deserialize, Serialize};

/// Padding strategies for different privacy/performance tradeoffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaddingMode {
    /// No padding. **Caution**: Leaks exact message size.
    None,
    /// Pad to 256-byte blocks. Suitable for short messages.
    Small,
    /// Pad to 1024-byte blocks. **Recommended default** for general messaging.
    Standard,
    /// Pad to 4096-byte blocks. Recommended for high-privacy applications.
    Large,
    /// Pad to 16384-byte blocks. Maximum metadata protection.
    Maximum,
    /// Fixed 64KB padding for all messages. Eliminates ALL message size signals for high-assurance.
    Quantum,
    /// Custom block size (must be a power of 2, minimum 64 bytes).
    Custom(usize),
}

impl PaddingMode {
    /// Returns the block size in bytes for this mode.
    pub fn block_size(&self) -> usize {
        match self {
            PaddingMode::None => 1,
            PaddingMode::Small => 256,
            PaddingMode::Standard => 1024,
            PaddingMode::Large => 4096,
            PaddingMode::Maximum => 16384,
            PaddingMode::Quantum => 65536,
            PaddingMode::Custom(n) => *n,
        }
    }

    /// Returns true if padding is enabled for this mode.
    pub fn is_enabled(&self) -> bool {
        !matches!(self, PaddingMode::None)
    }
}

/// Total non-plaintext overhead bytes in the padded format (v3.1.0)
/// [ 1-byte prefix_len | prefix_noise (1..8) | ... | 2-byte LE padding_len ]
pub const PADDING_MIN_OVERHEAD: usize = 1 + 1 + 2; 

/// Default padding block size (1024 bytes) — the most common choice for
/// general-purpose messaging. Exposed as a top-level constant so modules
/// outside `crypto` (e.g. `metadata`) can refer to it by its stable name.
pub const BLOCK_SIZE_STANDARD: usize = 1024;

/// Maximum padding that can be encoded in 2 bytes.
pub const MAX_PADDING_BYTES: usize = 65535;

/// SIBNA-2026-018 (PATCH 20): maximum number of *additional* full blocks
/// of random padding that may be appended on top of the minimum needed
/// to reach the next block boundary. With `MAX_EXTRA_BLOCKS = 7`, the
/// on-wire size of a given plaintext can occupy any of 8 distinct
/// padded sizes (the minimum-boundary size plus 0..7 extra blocks).
///
/// Chosen to keep the worst-case bandwidth overhead bounded (7 extra
/// blocks at the largest Quantum mode = 7 × 64 KiB = 448 KiB per
/// message) while still defeating simple per-size traffic analysis.
pub const MAX_EXTRA_BLOCKS: usize = 7;

/// Pad a plaintext message according to the specified mode.
///
/// Returns a buffer whose length is a multiple of the block size.
///
/// # V3.1.0 Hardening:
/// To prevent range inference attacks, we add 1-8 bytes of random noise at the
/// START of the message (Prefix Noise) and move the length field to the end.
/// The entire block is intended to be encrypted via AEAD.
///
/// # SIBNA-2026-018 (PATCH 20):
/// In addition to the existing per-call randomness (prefix_len, prefix_noise,
/// random padding bytes), the **per-block suffix length** is now drawn
/// uniformly from `0..MAX_EXTRA_BLOCKS` additional full blocks. This makes
/// the on-wire size of two messages with identical plaintext length
/// no longer deterministic — an observer cannot group messages by their
/// padded size with high confidence. The length is still encoded in the
/// trailing 2-byte LE field so `unpad_message` recovers the exact
/// plaintext.
pub fn pad_message(plaintext: &[u8], mode: PaddingMode) -> ProtocolResult<Vec<u8>> {
    if !mode.is_enabled() {
        return Ok(plaintext.to_vec());
    }

    // Empty plaintext is ALLOWED — it is the carrier for cover (dummy) traffic.
    // Rejecting it breaks the privacy guarantee in `SecureContext::generate_cover_message`.
    if plaintext.is_empty() && !matches!(mode, PaddingMode::Quantum) {
        // For non-Quantum modes we still pad an empty message to a single block
        // (a fixed-size dummy indistinguishable from a real message). Callers
        // can request Quantum mode if they want a true zero-length carrier.
    }

    let mut rng = SecureRandom::new().map_err(|_| ProtocolError::InternalError)?;
    
    // 1. Generate random prefix noise (1 to 8 bytes)
    let prefix_len = (rng.next_u32() % 8 + 1) as usize;
    let mut prefix_noise = vec![0u8; prefix_len];
    rng.fill_bytes(&mut prefix_noise);

    let block = mode.block_size();

    // : Custom block size must be a power of two and at least 64 bytes.
    // Invalid block sizes produce non-aligned output that breaks unpad_message and
    // leaks message size information. debug_assert was insufficient (no-op in release).
    if let PaddingMode::Custom(n) = mode {
        if n == 0 || !n.is_power_of_two() || n < 64 {
            return Err(ProtocolError::InvalidArgument);
        }
    }
    let min_total = 1 + prefix_len + plaintext.len() + 2;

    // 2. Calculate minimum trailing bytes needed to reach block boundary
    let remainder = min_total % block;
    let min_pad_len = if remainder == 0 { 0 } else { block - remainder };

    // 3. SIBNA-2026-018: randomize the per-block suffix length so two
    //    messages of the same plaintext length don't necessarily produce
    //    the same on-wire size. We add 0..MAX_EXTRA_BLOCKS additional
    //    full blocks of random padding, but cap the random draw so the
    //    final pad_len always fits in the 2-byte length field and never
    //    exceeds MAX_PADDING_BYTES.
    let max_blocks_for_budget = MAX_PADDING_BYTES.saturating_sub(min_pad_len) / block;
    let cap = max_blocks_for_budget.min(MAX_EXTRA_BLOCKS);
    let extra_blocks = (rng.next_u32() % (cap as u32 + 1)) as usize;
    let pad_len = min_pad_len + extra_blocks * block;

    if pad_len > MAX_PADDING_BYTES {
        return Err(ProtocolError::InvalidArgument);
    }

    let total = min_total + pad_len;
    let mut output = Vec::with_capacity(total);

    // Format: [ 1-byte prefix_len | prefix_noise | plaintext | random_padding | 2-byte LE padding_len ]
    output.push(prefix_len as u8);
    output.extend_from_slice(&prefix_noise);
    output.extend_from_slice(plaintext);

    // 4. Fill trailing padding with random bytes (per-block nonce is implicit
    //    in the random byte stream — no two blocks are identical)
    if pad_len > 0 {
        let mut rand_buf = vec![0u8; pad_len];
        rng.fill_bytes(&mut rand_buf);
        output.extend_from_slice(&rand_buf);
    }

    // 5. Append 2-byte padding length info
    output.push((pad_len & 0xFF) as u8);
    output.push((pad_len >> 8) as u8);

    debug_assert_eq!(output.len() % block, 0, "padded size must be multiple of block");

    Ok(output)
}

/// Remove padding from a decrypted message.
pub fn unpad_message(padded: &[u8]) -> ProtocolResult<Vec<u8>> {
    if padded.len() < PADDING_MIN_OVERHEAD {
        return Err(ProtocolError::InvalidMessage);
    }

    // Read prefix length from start
    let prefix_len = padded[0] as usize;
    if !(1..=8).contains(&prefix_len) || 1 + prefix_len + 2 > padded.len() {
        return Err(ProtocolError::InvalidMessage);
    }

    // Read 2-byte LE trailing pad length from end
    let lo = padded[padded.len() - 2] as usize;
    let hi = padded[padded.len() - 1] as usize;
    let pad_len = lo | (hi << 8);

    let total_overhead = 1 + prefix_len + pad_len + 2;
    if total_overhead > padded.len() {
        return Err(ProtocolError::InvalidMessage);
    }

    let plaintext_len = padded.len() - total_overhead;
    let start = 1 + prefix_len;
    let end = start + plaintext_len;

    Ok(padded[start..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let msg = b"Hello, Sibna!";
        for mode in [PaddingMode::Small, PaddingMode::Standard, PaddingMode::Large, PaddingMode::Quantum] {
            let padded = pad_message(msg, mode).unwrap();
            // Padded size must be exact multiple of block
            assert_eq!(padded.len() % mode.block_size(), 0, "not aligned: {mode:?}");
            // Must recover original
            let recovered = unpad_message(&padded).unwrap();
            assert_eq!(recovered, msg, "roundtrip failed for {mode:?}");
        }
    }

    #[test]
    fn test_padding_hides_size() {
        let mode = PaddingMode::Standard;
        let msg1 = b"Short";
        let msg2 = b"A bit longer message";

        let padded1 = pad_message(msg1, mode).unwrap();
        let padded2 = pad_message(msg2, mode).unwrap();

        // SIBNA-2026-018 (PATCH 20): the on-wire size is no longer
        // *deterministic* — each call can pick 0..MAX_EXTRA_BLOCKS extra
        // blocks. Both messages must still be aligned to the block size.
        assert_eq!(padded1.len() % mode.block_size(), 0);
        assert_eq!(padded2.len() % mode.block_size(), 0);
        // Padded sizes are now >= 1024 (one block) but no longer == 1024.
        assert!(padded1.len() >= 1024);
        assert!(padded2.len() >= 1024);
        assert!(padded1.len() <= 1024 + 7 * 1024);
        assert!(padded2.len() <= 1024 + 7 * 1024);

        // Roundtrip still recovers the exact plaintext.
        assert_eq!(unpad_message(&padded1).unwrap(), msg1);
        assert_eq!(unpad_message(&padded2).unwrap(), msg2);
    }

    #[test]
    fn test_prefix_noise_randomness() {
        let msg = b"Same message";
        let mode = PaddingMode::Standard;

        let padded1 = pad_message(msg, mode).unwrap();
        let padded2 = pad_message(msg, mode).unwrap();

        // Even with same message and same mode, the padded buffer should be different
        // due to random prefix_len, random noise, and (PATCH 20) random extra blocks.
        assert_ne!(padded1, padded2);
    }

    // SIBNA-2026-018 regression: over many calls, the padded on-wire size
    // for a fixed plaintext should hit at least 2 distinct values.
    // With 8 possible sizes (1 minimum + 0..7 extra blocks) and 32 trials,
    // the probability of all 32 picking the same size is (1/8)^31 ≈ 0,
    // so this test is a strong (probabilistic) check that the
    // randomization is in effect.
    #[test]
    fn test_padding_size_distribution_not_constant() {
        let mode = PaddingMode::Standard;
        let msg = b"constant-size message";
        let mut sizes = std::collections::HashSet::new();
        for _ in 0..64 {
            let p = pad_message(msg, mode).unwrap();
            sizes.insert(p.len());
        }
        assert!(sizes.len() >= 2,
            "SIBNA-2026-018 regression: padded size for fixed plaintext is constant across \
             64 trials; only saw sizes {:?}. Expected at least 2 distinct sizes.",
            sizes);
        // And every size is aligned to the block.
        for s in &sizes {
            assert_eq!(s % mode.block_size(), 0);
        }
    }
}
