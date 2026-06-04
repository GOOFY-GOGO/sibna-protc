#![allow(missing_docs)]
//! Metadata Resistance Module
//!
//! Closes the final gap: even with Sealed Sender, an observer on the wire can:
//!   1. Correlate message SIZE (variable-length reveals content type)
//!   2. Correlate message TIMING (activity patterns reveal social graph)
//!
//! Solutions implemented here:
//!   - Constant-size padding (Hardened format from padding.rs)
//!   - Timing jitter: server delays delivery by a random 0-500ms
//!   - End-to-end signed envelope: protects against server tampering

use rand::Rng;

/// Target block size for padding (1024 bytes)
/// All messages are padded to the nearest multiple of this value
pub use crate::crypto::padding::BLOCK_SIZE_STANDARD as PADDING_BLOCK_SIZE;

/// Maximum random delivery jitter in milliseconds
pub const MAX_JITTER_MS: u64 = 500;

/// Pad a message payload to the nearest multiple of PADDING_BLOCK_SIZE
pub fn pad_payload(payload: &[u8]) -> Result<Vec<u8>, PaddingError> {
    crate::crypto::padding::pad_message(payload, crate::crypto::padding::PaddingMode::Standard)
        .map_err(|_| PaddingError::InvalidPadding)
}

/// Remove padding from a received payload
pub fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>, PaddingError> {
    crate::crypto::padding::unpad_message(padded).map_err(|_| PaddingError::InvalidPadding)
}

#[allow(dead_code)]
fn round_up_to_block(len: usize) -> usize {
    if len == 0 {
        return PADDING_BLOCK_SIZE;
    }
    ((len + PADDING_BLOCK_SIZE - 1) / PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE
}

/// Get a random delivery jitter delay
pub fn random_jitter_ms() -> u64 {
    rand::thread_rng().gen_range(0..=MAX_JITTER_MS)
}

/// Padding error
#[derive(Debug, PartialEq)]
pub enum PaddingError {
    TooShort,
    InvalidPadding,
}

/// Signed envelope for end-to-end integrity
///
/// Protects against a compromised server modifying the envelope
/// (changing recipient, injecting messages, altering timestamps).
///
/// The sender signs:
///   SHA-512(recipient_id || payload_hex || timestamp || message_id)
/// using their Ed25519 identity key.
///
/// The recipient MUST verify this signature before decrypting.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedEnvelope {
    /// Recipient identity key hex (target)
    pub recipient_id: String,
    /// Encrypted payload hex (Double Ratchet output)
    pub payload_hex: String,
    /// Sender's identity key hex (visible to recipient, hidden from server)
    pub sender_id: String,
    /// Unix timestamp
    pub timestamp: i64,
    /// Unique message ID
    pub message_id: String,
    /// Ed25519 signature over SHA-512(recipient_id || payload_hex || timestamp || message_id || is_dummy)
    pub signature_hex: String,
    /// LZ4 compressed?
    pub compressed: bool,
    /// Is this a dummy packet (Cover Traffic)?
    pub is_dummy: bool,
}

impl SignedEnvelope {
    /// Compute the canonical signing payload
    pub fn signing_payload(&self) -> Vec<u8> {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(self.recipient_id.as_bytes());
        hasher.update(self.payload_hex.as_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.message_id.as_bytes());
        hasher.update(&[self.is_dummy as u8]);
        hasher.finalize().to_vec()
    }

    /// Verify the Ed25519 signature
    pub fn verify(&self) -> Result<(), EnvelopeError> {
        let sig_bytes =
            hex::decode(&self.signature_hex).map_err(|_| EnvelopeError::MalformedSignature)?;
        let key_bytes =
            hex::decode(&self.sender_id).map_err(|_| EnvelopeError::MalformedSenderKey)?;

        if key_bytes.len() != 32 || sig_bytes.len() != 64 {
            return Err(EnvelopeError::MalformedSignature);
        }

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| EnvelopeError::MalformedSenderKey)?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| EnvelopeError::MalformedSignature)?;

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk =
            VerifyingKey::from_bytes(&key_array).map_err(|_| EnvelopeError::InvalidSenderKey)?;
        let sig = Signature::from_bytes(&sig_array);
        let payload = self.signing_payload();

        vk.verify(&payload, &sig)
            .map_err(|_| EnvelopeError::SignatureInvalid)
    }

    /// Check if the envelope is expired (more than 5 minutes old)
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        (now - self.timestamp).abs() > 300
    }
}

/// Envelope error
#[derive(Debug)]
pub enum EnvelopeError {
    MalformedSignature,
    MalformedSenderKey,
    InvalidSenderKey,
    SignatureInvalid,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_roundtrip_small() {
        let payload = b"Hello Sibna!";
        let padded = pad_payload(payload).expect("pad small");
        // SIBNA-2026-018 (PATCH 20): on-wire size is no longer
        // deterministic; minimum is one block, max is 1 + 7 = 8 blocks.
        assert!(padded.len() >= PADDING_BLOCK_SIZE);
        assert!(padded.len() <= 8 * PADDING_BLOCK_SIZE);
        assert_eq!(padded.len() % PADDING_BLOCK_SIZE, 0);
        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(unpadded, payload);
    }

    #[test]
    fn test_padding_roundtrip_large() {
        let payload = vec![0xABu8; 1025];
        let padded = pad_payload(&payload).expect("pad large");
        // SIBNA-2026-018 (PATCH 20): the on-wire size is no longer
        // *deterministic* — PATCH 20 adds 0..7 extra full blocks of
        // random padding. The minimum is 2*BLOCK_SIZE; the maximum
        // is 2*BLOCK_SIZE + 7*BLOCK_SIZE = 9*BLOCK_SIZE.
        assert!(padded.len() >= 2 * PADDING_BLOCK_SIZE);
        assert!(padded.len() <= (2 + 7) * PADDING_BLOCK_SIZE);
        assert_eq!(padded.len() % PADDING_BLOCK_SIZE, 0);
        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(unpadded, payload);
    }

    #[test]
    fn test_padding_size_indistinguishable() {
        // SIBNA-2026-018 (PATCH 20): exact on-wire size is no longer
        // deterministic. Two messages of different sizes each pick
        // independently from 0..7 extra blocks, so their padded
        // sizes may differ. The invariant is: both fit in the same
        // block range [BLOCK_SIZE, 8*BLOCK_SIZE], and both are
        // indistinguishable to an observer who doesn't know the
        // extra-block draw.
        let small = b"Hi";
        let medium = vec![0u8; 800];
        let s = pad_payload(small).expect("a").len();
        let m = pad_payload(&medium).expect("b").len();
        assert!((PADDING_BLOCK_SIZE..=8 * PADDING_BLOCK_SIZE).contains(&s));
        assert!((PADDING_BLOCK_SIZE..=8 * PADDING_BLOCK_SIZE).contains(&m));
        assert_eq!(s % PADDING_BLOCK_SIZE, 0);
        assert_eq!(m % PADDING_BLOCK_SIZE, 0);
    }

    #[test]
    fn test_jitter_range() {
        for _ in 0..100 {
            let j = random_jitter_ms();
            assert!(j <= MAX_JITTER_MS);
        }
    }
}
