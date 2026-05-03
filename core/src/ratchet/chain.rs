use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use crate::crypto::{CryptoError, CryptoResult};

const MESSAGE_KEY_SEED: u8 = 0x01;
const CHAIN_KEY_SEED:   u8 = 0x02;
const HEADER_KEY_SEED:  u8 = 0x03;

#[derive(Serialize, Deserialize)]
pub struct ChainKey {
    pub key: [u8; 32],
    pub index: u64,
    pub created_at: u64,
    pub max_messages: u64,
    pub reserved_until: u64,
}

impl ChainKey {
    pub const DEFAULT_MAX_MESSAGES: u64 = 1000;

    pub fn new(key: [u8; 32]) -> Self {
        let created_at = crate::crypto::current_timestamp().unwrap_or(0);
        Self {
            key,
            index: 0,
            created_at,
            max_messages: Self::DEFAULT_MAX_MESSAGES,
            reserved_until: Self::DEFAULT_MAX_MESSAGES,
        }
    }

    pub fn with_max_messages(key: [u8; 32], max_messages: u64) -> Self {
        let mut ck = Self::new(key);
        ck.max_messages = max_messages;
        ck.reserved_until = max_messages;
        ck
    }

    pub fn next_message_key(&mut self) -> Option<[u8; 32]> {
        if self.index >= self.max_messages { return None; }
        let message_key = self.derive_key(MESSAGE_KEY_SEED).ok()?;
        let next_chain  = self.derive_key(CHAIN_KEY_SEED).ok()?;
        self.key.zeroize();
        self.key   = next_chain;
        self.index += 1;
        Some(message_key)
    }

    /// Header encryption is not yet applied on the wire (planned for v3.1).
    /// The DH public key and message number are currently transmitted in plaintext.
    pub fn derive_header_key(&self) -> Option<[u8; 32]> {
        self.derive_key(HEADER_KEY_SEED).ok()
    }

    fn derive_key(&self, seed: u8) -> CryptoResult<[u8; 32]> {
        let mut h = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        h.update(&[seed]);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize().into_bytes()[..32]);
        Ok(out)
    }

    pub fn index(&self) -> u64           { self.index }
    pub fn clone_key(&self) -> [u8; 32]  { self.key }
    pub fn remaining_messages(&self) -> u64 { self.max_messages.saturating_sub(self.index) }

    pub fn age_secs(&self) -> u64 {
        crate::crypto::current_timestamp()
            .unwrap_or(self.created_at)
            .saturating_sub(self.created_at)
    }

    pub fn needs_rotation(&self) -> bool {
        self.index >= self.max_messages || self.age_secs() > 86400
    }
}

impl Clone for ChainKey {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            index: self.index,
            created_at: self.created_at,
            max_messages: self.max_messages,
            reserved_until: self.reserved_until,
        }
    }
}

impl Zeroize for ChainKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.index        = 0;
        self.reserved_until = 0;
    }
}

impl ZeroizeOnDrop for ChainKey {}
impl Drop for ChainKey { fn drop(&mut self) { self.zeroize(); } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_produces_distinct_keys() {
        let mut chain = ChainKey::new([0x42u8; 32]);
        let k0 = chain.next_message_key().unwrap();
        let k1 = chain.next_message_key().unwrap();
        let k2 = chain.next_message_key().unwrap();
        assert_ne!(k0, k1);
        assert_ne!(k1, k2);
        assert_eq!(chain.index(), 3);
    }

    #[test]
    fn exhausted_chain_returns_none() {
        let mut chain = ChainKey::with_max_messages([0x01u8; 32], 2);
        assert!(chain.next_message_key().is_some());
        assert!(chain.next_message_key().is_some());
        assert!(chain.next_message_key().is_none());
    }
}
