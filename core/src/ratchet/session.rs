//! Double Ratchet Session
//!
//! FIXES:
//! - HKDF: Two expand() on same PRK replaced with single 64-byte expand + split
//! - Encryptor initial_message_number=u64::MAX -> 0 (correct semantics)
//! - skip_message_keys: all unwrap() replaced with proper ? propagation
//! - perform_handshake: shared_secret no longer returned to caller

use super::{ChainKey, DoubleRatchetState, RatchetHeader, RatchetMessage, RatchetConfig, ENCRYPTED_HEADER_SIZE};
use super::super::crypto::{Encryptor, SecureRandom, RatchetKdf};
use super::super::error::{ProtocolError, ProtocolResult};
use super::super::validation::{validate_message, validate_associated_data};
use super::super::handshake::HandshakeRole;
use crate::Config;
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use parking_lot::RwLock;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

/// Double Ratchet Session - manages state and cryptographic operations for a secure channel.
#[derive(Serialize, Deserialize)]
pub struct DoubleRatchetSession {
    #[serde(with = "crate::crypto::serde_helpers::rw_lock_serde")]
    state: RwLock<DoubleRatchetState>,
    config: Config,
    _ratchet_config: RatchetConfig,
    session_id: String,
    peer_id: Option<String>,
    /// Unix timestamp when session was created
    created_at_ts: u64,
}

#[allow(missing_docs)]
impl DoubleRatchetSession {
    pub fn new(config: Config) -> ProtocolResult<Self> {
        let mut rng = crate::crypto::SecureRandom::new()
            .map_err(|_| ProtocolError::InternalError)?;
        
        let mut dh_local_bytes = [0u8; 32];
        rng.fill_bytes(&mut dh_local_bytes);
        let dh_local = StaticSecret::from(dh_local_bytes);
        // store PUBLIC key, not the private scalar
        let dh_public_bytes = PublicKey::from(&dh_local).as_bytes().to_vec();
        dh_local_bytes.zeroize(); // Wipe private scalar temp buffer immediately
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        let state = DoubleRatchetState {
            root_key: [0u8; 32],
            sending_chain: None,
            receiving_chain: None,
            dh_local: Some(dh_local),
            dh_local_bytes: dh_public_bytes, // public key bytes only
            dh_remote: None,
            dh_remote_bytes: None,
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
            created_at: now,
            last_activity: now,
            version: DoubleRatchetState::CURRENT_VERSION,
            messages_sent: 0,
            messages_received: 0,
        };

        let session_id = Self::generate_session_id()?;
        Ok(Self {
            state: RwLock::new(state),
            config: config.clone(),
            _ratchet_config: RatchetConfig::default(),
            session_id,
            peer_id: None,

            created_at_ts: now,
        })
    }

    /// HKDF now uses single 64-byte expand then splits into root_key + chain_key.
    /// Previously two separate expand() calls on the same PRK with no salt were used,
    /// which while not catastrophically broken, is non-standard and wastes KDF strength.
    pub fn from_shared_secret(
        shared_secret: &[u8; 32],
        local_dh: StaticSecret,
        remote_dh: PublicKey,
        config: Config,
        role: HandshakeRole,
    ) -> ProtocolResult<Self> {
        if shared_secret.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidArgument);
        }

        // Single HKDF expand for 64 bytes, split into root_key (32) + chain_key (32)
        let hkdf = Hkdf::<Sha256>::new(Some(b"SibnaSession_v3"), shared_secret);
        let mut okm = [0u8; 64];
        hkdf.expand(b"SibnaRootAndChainKey_v3", &mut okm)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        let mut root_key = [0u8; 32];
        let mut chain_key = [0u8; 32];
        root_key.copy_from_slice(&okm[..32]);
        chain_key.copy_from_slice(&okm[32..]);
        okm.zeroize();

        let (sending_chain, receiving_chain) = if role.is_initiator() {
            (Some(ChainKey::new(chain_key)), None)
        } else {
            (None, Some(ChainKey::new(chain_key)))
        };

        // dh_local_bytes stores the PUBLIC key only
        let dh_local_bytes = PublicKey::from(&local_dh).as_bytes().to_vec();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        let state = DoubleRatchetState {
            root_key,
            sending_chain,
            receiving_chain,
            dh_local: Some(local_dh),
            dh_local_bytes,
            dh_remote: Some(remote_dh),
            dh_remote_bytes: Some(remote_dh.as_bytes().to_vec()),
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
            created_at: now,
            last_activity: now,
            version: DoubleRatchetState::CURRENT_VERSION,
            messages_sent: 0,
            messages_received: 0,
        };

        let session_id = Self::generate_session_id()?;
        Ok(Self {
            state: RwLock::new(state),
            config: config.clone(),
            _ratchet_config: RatchetConfig::default(),
            session_id,
            peer_id: None,

            created_at_ts: now,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        validate_message(plaintext).map_err(|_| ProtocolError::InvalidMessage)?;
        validate_associated_data(associated_data).map_err(|_| ProtocolError::InvalidArgument)?;

        let mut state = self.state.write();

        let mut rotated = false;
        if state.sending_chain.as_ref().map(|c| c.needs_rotation()).unwrap_or(true) {
            self.perform_dh_ratchet(&mut state)?;
            rotated = true;
        }

        let dh_pub = state.dh_local.as_ref()
            .map(PublicKey::from)
            .ok_or(ProtocolError::InvalidState)?;

        let sending_chain = state.sending_chain.as_mut()
            .ok_or(ProtocolError::InvalidState)?;

        // Derive header key from sending chain BEFORE advancing (next_message_key advances chain)
        let header_key = sending_chain.derive_header_key()
            .ok_or(ProtocolError::InvalidState)?;

        // Nonce Safety Check 
        if sending_chain.index >= sending_chain.reserved_until {
            return Err(ProtocolError::NonceReservationRequired);
        }

        let message_key = sending_chain.next_message_key()
            .ok_or(ProtocolError::InvalidState)?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        let header = RatchetHeader {
            dh_public: *dh_pub.as_bytes(),
            message_number: sending_chain.index() - 1,
            previous_chain_length: state.previous_counter,
            timestamp,
        };

        header.validate()?;

        // initial_message_number=0, not u64::MAX. The Encryptor's counter
        // tracks its own sequence; using MAX was a logic error that could cause
        // wrapping issues and bypasses replay detection on first message.
        let mut encryptor = Encryptor::new(&message_key, 0)
            .map_err(ProtocolError::from)?;

        let header_bytes = header.to_bytes();
        let mut final_ad = Vec::with_capacity(associated_data.len() + header_bytes.len());
        final_ad.extend_from_slice(associated_data);
        final_ad.extend_from_slice(&header_bytes);

        let ciphertext = encryptor.encrypt_message(plaintext, &final_ad)
            .map_err(ProtocolError::from)?;

        let message = RatchetMessage { header, ciphertext };

        state.touch();
        state.messages_sent += 1;

        // v3.1: encrypt header before sending on wire (when enabled)
        // SECURITY: If we just rotated the DH key, the header MUST be plaintext
        // so the receiver can see the new dh_public and perform their own ratchet.
        if self.config.enable_header_encryption && !rotated {
            message.to_bytes_encrypted(&header_key)
        } else {
            Ok(message.to_bytes())
        }
    }

    pub fn decrypt(&self, message: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        if message.len() < 48 + 29 {
            return Err(ProtocolError::InvalidMessage);
        }

        let mut state = self.state.write();

        // v3.1: Try to decrypt as encrypted header
        // First, we need to figure out which header key to use.
        // If the message triggers a DH ratchet, we need to do the ratchet first.
        let ratchet_message = if self.config.enable_header_encryption && message.len() >= ENCRYPTED_HEADER_SIZE + 29 {
            let mut decrypted = None;

            // Try receiving chain header key first (most common case)
            if let Some(ref chain) = state.receiving_chain {
                if let Some(hk) = chain.derive_header_key() {
                    if let Ok(msg) = RatchetMessage::from_bytes_encrypted(message, &hk) {
                        decrypted = Some(msg);
                    }
                }
            }

            // Try sending chain header key (for echo scenarios)
            if decrypted.is_none() {
                if let Some(ref chain) = state.sending_chain {
                    if let Some(hk) = chain.derive_header_key() {
                        if let Ok(msg) = RatchetMessage::from_bytes_encrypted(message, &hk) {
                            decrypted = Some(msg);
                        }
                    }
                }
            }

            match decrypted {
                Some(msg) => msg,
                None => {
                    // Can't decrypt header - this message likely requires a DH ratchet
                    // (e.g., after peer restored session). Try to extract plaintext
                    // header to determine if we need to ratchet, then retry.
                    //
                    // For now, fall back to plaintext header parsing which will
                    // trigger the DH ratchet in the normal path below.
                    RatchetMessage::from_bytes(message)?
                }
            }
        } else {
            RatchetMessage::from_bytes(message)?
        };

        let header = ratchet_message.header;
        header.validate()?;

        let remote_dh = PublicKey::from(header.dh_public);

        let key_tuple = (header.dh_public, header.message_number);
        if let Some(&mk) = state.skipped_message_keys.get(&key_tuple) {
            return self.decrypt_with_key(
                &mk, &ratchet_message.ciphertext, associated_data,
                &header, &mut state, &key_tuple,
            );
        }

        let result = {
            let mut state_clone = state.clone();
            let key_tuple_clone = (header.dh_public, header.message_number);

            let needs_ratchet = state_clone.dh_remote.as_ref()
                .map(|p| !crate::crypto::constant_time_eq(p.as_bytes(), remote_dh.as_bytes()))
                .unwrap_or(true);

            if needs_ratchet {
                if let Some(prev_counter) = state_clone.sending_chain.as_ref().map(|c| c.index()) {
                    state_clone.previous_counter = prev_counter;
                }
                self.skip_message_keys(&mut state_clone, header.previous_chain_length)?;
                self.dh_ratchet(&mut state_clone, remote_dh)?;
            }

            self.skip_message_keys(&mut state_clone, header.message_number)?;

            let mk = {
                let receiving_chain = state_clone.receiving_chain.as_mut()
                    .ok_or(ProtocolError::InvalidState)?;
                if header.message_number < receiving_chain.index() {
                    return Err(ProtocolError::ReplayAttackDetected);
                }
                receiving_chain.next_message_key().ok_or(ProtocolError::InvalidState)?
            };

            let decrypt_result = self.decrypt_with_key(
                &mk, &ratchet_message.ciphertext, associated_data,
                &header, &mut state_clone, &key_tuple_clone,
            );

            if decrypt_result.is_ok() {
                state_clone.touch();
                *state = state_clone; // Commit successful ratchet
                decrypt_result
            } else {
                state_clone.zeroize(); // Securely wipe failed trial state
                decrypt_result
            }
        };

        if result.is_ok() {
            state.messages_received += 1;
        }

        result
    }

    fn decrypt_with_key(
        &self, key: &[u8; 32], ciphertext: &[u8], associated_data: &[u8],
        header: &RatchetHeader, state: &mut DoubleRatchetState,
        key_tuple: &([u8; 32], u64),
    ) -> ProtocolResult<Vec<u8>> {
        // initial_message_number=0 (consistent with encrypt)
        let mut encryptor = Encryptor::new(key, 0).map_err(ProtocolError::from)?;

        let header_bytes = header.to_bytes();
        let mut full_ad = Vec::with_capacity(associated_data.len() + header_bytes.len());
        full_ad.extend_from_slice(associated_data);
        full_ad.extend_from_slice(&header_bytes);

        let result = encryptor.decrypt_message(ciphertext, &full_ad).map_err(ProtocolError::from);

        if result.is_ok() {
            state.skipped_message_keys.remove(key_tuple);
        }

        result
    }

    /// All unwrap() replaced with ? operator - no more panics on malformed messages.
    fn skip_message_keys(&self, state: &mut DoubleRatchetState, until_n: u64) -> ProtocolResult<()> {
        if state.receiving_chain.is_none() { return Ok(()); }

        let current_index = state.receiving_chain
            .as_ref()
            .ok_or(ProtocolError::InvalidState)?
            .index();

        if until_n > current_index + state.max_skip as u64 {
            return Err(ProtocolError::MaxSkippedMessagesExceeded);
        }

        while state.receiving_chain
            .as_ref()
            .ok_or(ProtocolError::InvalidState)?
            .index() < until_n
        {
            let mk = state.receiving_chain
                .as_mut()
                .ok_or(ProtocolError::InvalidState)?
                .next_message_key()
                .ok_or(ProtocolError::InvalidState)?;

            let dh_remote = state.dh_remote.ok_or(ProtocolError::InvalidState)?;

            let key_index = state.receiving_chain
                .as_ref()
                .ok_or(ProtocolError::InvalidState)?
                .index() - 1;

            if !state.add_skipped_key(*dh_remote.as_bytes(), key_index, mk) {
                return Err(ProtocolError::MaxSkippedMessagesExceeded);
            }
        }
        Ok(())
    }

    fn dh_ratchet(&self, state: &mut DoubleRatchetState, remote_dh: PublicKey) -> ProtocolResult<()> {
        state.previous_counter = state.sending_chain.as_ref().map(|c| c.index()).unwrap_or(0);
        state.set_remote_dh(remote_dh);

        let dh_local = state.dh_local.as_ref().ok_or(ProtocolError::InvalidState)?;
        let mut shared_secret = dh_local.diffie_hellman(&remote_dh);
        let (rk, receiving_key) = RatchetKdf::kdf_rk(&state.root_key, shared_secret.as_bytes())?;
        shared_secret.zeroize();
        
        state.root_key = *rk;
        state.receiving_chain = Some(ChainKey::new(*receiving_key));

        let new_local = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let mut shared_secret_send = new_local.diffie_hellman(&remote_dh);
        let (rk2, sending_key) = RatchetKdf::kdf_rk(&state.root_key, shared_secret_send.as_bytes())?;
        shared_secret_send.zeroize();

        state.root_key = *rk2;
        state.sending_chain = Some(ChainKey::new(*sending_key));
        state.set_local_dh(new_local);

        Ok(())
    }

    fn perform_dh_ratchet(&self, state: &mut DoubleRatchetState) -> ProtocolResult<()> {
        let new_local = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        if let Some(remote_dh) = state.dh_remote {
            let mut shared_secret = new_local.diffie_hellman(&remote_dh);
            let (rk, sending_key) = RatchetKdf::kdf_rk(&state.root_key, shared_secret.as_bytes())?;
            shared_secret.zeroize();
            state.root_key = *rk;
            state.sending_chain = Some(ChainKey::new(*sending_key));
        }
        state.set_local_dh(new_local);
        Ok(())
    }

    fn generate_session_id() -> ProtocolResult<String> {
        let mut rng = SecureRandom::new()?;
        let bytes = rng.gen_bytes(16);
        Ok(hex::encode(bytes))
    }

    pub fn session_id(&self) -> &str { &self.session_id }
    pub fn set_peer_id(&mut self, peer_id: String) { self.peer_id = Some(peer_id); }
    pub fn peer_id(&self) -> Option<&str> { self.peer_id.as_deref() }
    pub fn message_stats(&self) -> (u64, u64) {
        let state = self.state.read();
        (state.messages_sent, state.messages_received)
    }
    pub fn age(&self) -> std::time::Duration { 
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|e| { tracing::error!("clock regression in ratchet session: {:?}", e); std::time::Duration::from_secs(u64::MAX / 2) })
            .as_secs();
        std::time::Duration::from_secs(now.saturating_sub(self.created_at_ts))
    }
    pub fn state_summary(&self) -> super::state::StateSummary {
        self.state.read().summary()
    }
    /// Check if the session has expired
    pub fn is_expired(&self) -> bool { self.state.read().is_expired() }

    /// Serialize the current session state to bytes.
    ///
    /// Used for persistent storage of ratchet state.
    pub fn serialize_state(&self) -> ProtocolResult<Vec<u8>> {
        let state = self.state.read();
        bincode::serde::encode_to_vec(&*state, bincode::config::legacy())
            .map_err(|_| ProtocolError::SerializationError)
    }

    /// Restore session state from serialized bytes.
    ///
    /// SIBNA-2026-014 (PATCH 22): the loaded state is re-hydrated via
    /// `DoubleRatchetState::restore_dh_keys` so that the `dh_remote`
    /// public key is reconstructed from its serialized bytes (the
    /// `dh_remote` field itself is `#[serde(skip)]` — only the bytes
    /// round-trip). After re-hydration, if `dh_local` is `None`
    /// (always the case after restore — the private scalar is never
    /// persisted) AND `dh_remote` is `Some`, we perform a fresh DH
    /// ratchet step to generate a new ephemeral `dh_local` and
    /// re-derive `root_key` and `sending_chain`. The peer's session
    /// will detect the new `dh_public` in the header and perform its
    /// own ratchet step to match — which is the correct,
    /// spec-compliant behavior for a session restored mid-conversation.
    ///
    /// Without this fresh ratchet, the first `encrypt()` call after
    /// restore would fail with `InvalidState` because `dh_local` was
    /// `None` and the encrypt path requires it to construct the
    /// header.
    pub fn deserialize_state(&self, data: &[u8]) -> ProtocolResult<()> {
        let mut loaded: DoubleRatchetState = bincode::serde::decode_from_slice(data, bincode::config::legacy()).map(|(v,_)|v)
            .map_err(|_| ProtocolError::DeserializationError)?;

        // Re-hydrate the remote public key from its serialized bytes
        // (dh_remote itself is serde-skipped). Private scalar dh_local
        // stays None — a fresh key pair is generated on the next
        // outgoing ratchet step.
        loaded.restore_dh_keys()
            .map_err(|_| ProtocolError::DeserializationError)?;

        {
            let mut state = self.state.write();
            *state = loaded;
            let max_skip = state.max_skip;

            // SIBNA-2026-014: prime the ratchet if needed so the
            // session is fully ready to send. We perform the ratchet
            // here (with the write lock already held) so the caller
            // doesn't have to special-case the post-restore path.
            //
            // Only ratchet if:
            // - dh_local is None (always true after restore, since the
            //   private scalar is intentionally not persisted).
            // - dh_remote is Some (we have a peer to ratchet against).
            // - We actually have a sending_chain to rotate (otherwise
            //   the ratchet would create one and orphan the original).
            //
            // If any of these are not met, we leave the state as-is
            // and the next encrypt() call will either succeed (if a
            // fresh session via `from_shared_secret` is set up
            // properly) or fail with a clear error.
            if state.dh_local.is_none()
                && state.dh_remote.is_some()
                && state.sending_chain.is_some()
            {
                self.perform_dh_ratchet(&mut state)?;
            }

            let mut entries: Vec<_> = state.skipped_message_keys.clone().into_iter().collect();
            entries.sort_by_key(|((_, n), _)| *n);
            entries.reverse();
            entries.truncate(max_skip);
            state.skipped_message_keys = entries.into_iter().collect();
        }

        Ok(())
    }

    /// Jump the sending ratchet to the reserved index 
    pub fn jump_to_reservation(&self) -> ProtocolResult<()> {
        let mut state = self.state.write();
        if let Some(ref mut ck) = state.sending_chain {
            if ck.reserved_until > ck.index {
                ck.index = ck.reserved_until;
                state.touch();
            }
        }
        Ok(())
    }

    /// Reserve nonces for future sends 
    pub fn reserve_nonces(&self, count: u64) -> ProtocolResult<()> {
        let mut state = self.state.write();
        if let Some(ref mut ck) = state.sending_chain {
            ck.reserved_until = ck.index.saturating_add(count);
            state.touch();
        }
        Ok(())
    }
}

impl Zeroize for DoubleRatchetSession {
    fn zeroize(&mut self) {
        // state contains ZeroizeOnDrop fields (root_key, chain keys, DH keys)
        // They are zeroed when state is dropped via DoubleRatchetState::zeroize()
        if let Some(mut state) = self.state.try_write() {
            state.zeroize();
        }
    }
}


impl Drop for DoubleRatchetSession {
    fn drop(&mut self) {}
}

impl ZeroizeOnDrop for DoubleRatchetSession {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        assert!(DoubleRatchetSession::new(Config::default()).is_ok());
    }

    #[test]
    fn test_session_from_shared_secret() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];
        let local_dh = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let remote_dh = PublicKey::from(&StaticSecret::random_from_rng(&mut rand_core::OsRng));
        assert!(DoubleRatchetSession::from_shared_secret(&shared_secret, local_dh, remote_dh, config, HandshakeRole::Initiator).is_ok());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);

        let s1 = DoubleRatchetSession::from_shared_secret(&shared_secret, sk1, pk2, config.clone(), HandshakeRole::Initiator).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(&shared_secret, sk2, pk1, config, HandshakeRole::Responder).unwrap();

        let plaintext = b"Hello Production!";
        let ad = b"aad";
        let ct = s1.encrypt(plaintext, ad).unwrap();
        let pt = s2.decrypt(&ct, ad).unwrap();
        assert_eq!(plaintext.to_vec(), pt);
    }

    #[test]
    fn test_replay_protection() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);
        let s1 = DoubleRatchetSession::from_shared_secret(&shared_secret, sk1, pk2, config.clone(), HandshakeRole::Initiator).unwrap();
        let s2 = DoubleRatchetSession::from_shared_secret(&shared_secret, sk2, pk1, config, HandshakeRole::Responder).unwrap();
        let ct = s1.encrypt(b"test", b"ad").unwrap();
        let _ = s2.decrypt(&ct, b"ad").unwrap();
        assert!(s2.decrypt(&ct, b"ad").is_err());
    }

    // SIBNA-2026-014 regression: a session restored from
    // serialize_state / deserialize_state must be able to **send**
    // messages again. The pre-PATCH-22 deserialize_state did not call
    // restore_dh_keys(), so the deserialized session had
    // `dh_remote = None` and the first encrypt() would fail
    // (perform_dh_ratchet skipped the DH step and the resulting
    // sending chain was based on the wrong root_key).
    #[test]
    fn test_serialize_deserialize_roundtrip_can_send() {
        let config = Config::default();
        let shared_secret = [0x77u8; 32];
        let sk1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pk2 = PublicKey::from(&sk2);

        // Establish a real session between Alice (initiator) and Bob (responder).
        let alice = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk1.clone(), pk2, config.clone(), HandshakeRole::Initiator,
        ).unwrap();
        let bob = DoubleRatchetSession::from_shared_secret(
            &shared_secret, sk2.clone(), pk1, config.clone(), HandshakeRole::Responder,
        ).unwrap();

        // Alice sends one message; Bob decrypts.
        let ct0 = alice.encrypt(b"first message", b"ad").unwrap();
        assert_eq!(bob.decrypt(&ct0, b"ad").unwrap(), b"first message");

        // Alice serializes her state, then a *fresh* session is
        // constructed (simulating an app restart). The fresh session
        // has no DH keys, no chains — only the deserialized state.
        let serialized = alice.serialize_state().unwrap();

        let alice_restored = DoubleRatchetSession::new(config.clone()).unwrap();
        assert!(alice_restored.deserialize_state(&serialized).is_ok());

        // After restore: alice_restored should be able to send.
        // The first send will perform a fresh DH ratchet (dh_local
        // was None) and the message must be decryptable by Bob.
        let ct1 = alice_restored
            .encrypt(b"after restore", b"ad")
            .expect("SIBNA-2026-014 regression: encrypt() failed after deserialize_state");
        assert_eq!(
            bob.decrypt(&ct1, b"ad").unwrap(),
            b"after restore",
            "Bob could not decrypt Alice's post-restore ciphertext"
        );

        // And Bob can still reply to the restored Alice.
        let ct2 = bob.encrypt(b"reply", b"ad").unwrap();
        assert_eq!(
            alice_restored.decrypt(&ct2, b"ad").unwrap(),
            b"reply",
            "Alice (restored) could not decrypt Bob's reply"
        );
    }
}
