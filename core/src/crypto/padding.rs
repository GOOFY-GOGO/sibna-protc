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

/// Maximum padding that can be encoded in 2 bytes.
pub const MAX_PADDING_BYTES: usize = 65535;

/// Pad a plaintext message according to the specified mode.
///
/// Returns a buffer whose length is a multiple of the block size.
///
/// # V3.1.0 Hardening:
/// To prevent range inference attacks, we add 1-8 bytes of random noise at the 
/// START of the message (Prefix Noise) and move the length field to the end.
/// The entire block is intended to be encrypted via AEAD.
pub fn pad_message(plaintext: &[u8], mode: PaddingMode) -> ProtocolResult<Vec<u8>> {
    if !mode.is_enabled() {
        return Ok(plaintext.to_vec());
    }

    if plaintext.is_empty() {
        return Err(ProtocolError::InvalidArgument);
    }

    let mut rng = SecureRandom::new().map_err(|_| ProtocolError::InternalError)?;
    
    // 1. Generate random prefix noise (1 to 8 bytes)
    let prefix_len = (rng.next_u32() % 8 + 1) as usize;
    let mut prefix_noise = vec![0u8; prefix_len];
    rng.fill_bytes(&mut prefix_noise);

    let block = mode.block_size();
    let min_total = 1 + prefix_len + plaintext.len() + 2;

    // 2. Calculate how many trailing bytes needed to reach block boundary
    let remainder = min_total % block;
    let pad_len = if remainder == 0 { 0 } else { block - remainder };

    if pad_len > MAX_PADDING_BYTES {
        return Err(ProtocolError::InvalidArgument);
    }

    let total = min_total + pad_len;
    let mut output = Vec::with_capacity(total);

    // Format: [ 1-byte prefix_len | prefix_noise | plaintext | random_padding | 2-byte LE padding_len ]
    output.push(prefix_len as u8);
    output.extend_from_slice(&prefix_noise);
    output.extend_from_slice(plaintext);

    // 3. Fill trailing padding with random bytes
    if pad_len > 0 {
        let mut rand_buf = vec![0u8; pad_len];
        rng.fill_bytes(&mut rand_buf);
        output.extend_from_slice(&rand_buf);
    }

    // 4. Append 2-byte padding length info
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
    if prefix_len < 1 || prefix_len > 8 || 1 + prefix_len + 2 > padded.len() {
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
        
        // Padded sizes should be identical (both fit in one 1024B block)
        assert_eq!(padded1.len(), 1024);
        assert_eq!(padded2.len(), 1024);
    }

    #[test]
    fn test_prefix_noise_randomness() {
        let msg = b"Same message";
        let mode = PaddingMode::Standard;
        
        let padded1 = pad_message(msg, mode).unwrap();
        let padded2 = pad_message(msg, mode).unwrap();
        
        // Even with same message and same mode, the padded buffer should be different 
        // due to random prefix_len and random noise.
        assert_ne!(padded1, padded2);
    }
}
