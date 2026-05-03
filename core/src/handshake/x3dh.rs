//! X3DH Core Implementation
//!
//! Low-level X3DH operations with constant-time guarantees.

use crate::error::{ProtocolError, ProtocolResult};
use crate::crypto::{constant_time_eq, X3dhKdf};
use x25519_dalek::{StaticSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X3DH key agreement result
#[derive(Clone, Debug)]
pub struct X3dhResult {
    /// Shared secret
    pub shared_secret: [u8; 32],
    /// DH results used in derivation
    pub dh_results: Vec<[u8; 32]>,
    /// Post-Quantum Ciphertext (ML-KEM-768)
    #[cfg(feature = "pqc")]
    pub pq_ciphertext: Option<Vec<u8>>,
}

impl X3dhResult {
    /// Create a new X3DH result
    /// Creates an X3DH result. DH intermediates are stored and zeroized on Drop.
    /// NOTE: Do NOT zeroize here — the values are needed until Drop.
    pub fn new(shared_secret: [u8; 32], dh_results: Vec<[u8; 32]>) -> Self {
        Self {
            shared_secret,
            dh_results,
            #[cfg(feature = "pqc")]
            pq_ciphertext: None,
        }
    }

    /// Add PQC ciphertext
    #[cfg(feature = "pqc")]
    pub fn with_pq_ciphertext(mut self, ct: Vec<u8>) -> Self {
        self.pq_ciphertext = Some(ct);
        self
    }

    /// Validate the result
    pub fn validate(&self) -> ProtocolResult<()> {
        // Check shared secret is not all zeros
        if self.shared_secret.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidArgument);
        }

        // Check we have the expected number of DH results
        if self.dh_results.is_empty() || self.dh_results.len() > 4 {
            return Err(ProtocolError::InvalidArgument);
        }

        #[cfg(feature = "pqc")]
        if let Some(ref ct) = self.pq_ciphertext {
            if ct.len() != 1088 {
                return Err(ProtocolError::InvalidArgument);
            }
        }

        Ok(())
    }
}

impl Zeroize for X3dhResult {
    fn zeroize(&mut self) {
        self.shared_secret.zeroize();
        for dh in &mut self.dh_results {
            dh.zeroize();
        }
    }
}

impl ZeroizeOnDrop for X3dhResult {}

impl Drop for X3dhResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Perform X3DH key agreement (initiator)
///
/// # Arguments
/// * `our_identity` - Our identity secret key
/// * `our_ephemeral` - Our ephemeral secret key
/// * `peer_identity` - Peer's identity public key
/// * `peer_signed_prekey` - Peer's signed prekey public key
/// * `peer_onetime_prekey` - Peer's one-time prekey public key (optional)
/// * `peer_pq_pk` - Peer's Post-Quantum public key (optional, ML-KEM-768)
///
/// # Returns
/// X3DH result containing shared secret
pub fn x3dh_initiator_v3(
    our_identity: &StaticSecret,
    our_ephemeral: &StaticSecret,
    peer_identity: &PublicKey,
    peer_signed_prekey: &PublicKey,
    peer_onetime_prekey: Option<&PublicKey>,
    #[cfg(feature = "pqc")]
    peer_pq_pk: Option<&Vec<u8>>,
    our_device_id: &[u8; 16],
    peer_device_id: &[u8; 16],
    transcript_hash_ext: &[u8; 32],
) -> ProtocolResult<X3dhResult> {
    // DH1: Our identity + peer's signed prekey
    let dh1 = our_identity.diffie_hellman(peer_signed_prekey);

    // DH2: Our ephemeral + peer's identity
    let dh2 = our_ephemeral.diffie_hellman(peer_identity);

    // DH3: Our ephemeral + peer's signed prekey
    let dh3 = our_ephemeral.diffie_hellman(peer_signed_prekey);

    // DH4: Our ephemeral + peer's one-time prekey (if available)
    let dh4 = peer_onetime_prekey.map(|opk| {
        our_ephemeral.diffie_hellman(opk)
    });

    // Collect DH results
    let mut dh_results = vec![
        dh1.to_bytes(),
        dh2.to_bytes(),
        dh3.to_bytes(),
    ];

    if let Some(ref dh4) = dh4 {
        dh_results.push(dh4.to_bytes());
    }

    // Derive transcript hash 
    // IMPORTANT: Only hash PUBLIC key material to ensure consistency and prevent leakage.
    let mut hasher = blake3::Hasher::new();
    hasher.update(PublicKey::from(our_identity).as_bytes());
    hasher.update(PublicKey::from(our_ephemeral).as_bytes());
    hasher.update(peer_identity.as_bytes());
    hasher.update(peer_signed_prekey.as_bytes());
    if let Some(prekey) = peer_onetime_prekey {
        hasher.update(prekey.as_bytes());
    }
    hasher.update(our_device_id);
    hasher.update(peer_device_id);
    let transcript_hash: [u8; 32] = hasher.finalize().into();

    // Replace XOR-based external transcript binding with HKDF-based combining.
    //
    // OLD CODE: for i in 0..32 { transcript_hash[i] ^= transcript_hash_ext[i]; }
    // PROBLEM:  XOR with transcript_hash_ext = [0u8; 32] (the default for non-P2P flows)
    //           is an identity operation — it provides ZERO additional binding.
    //           Even with a non-zero ext, XOR is not a secure combining function
    //           (it is not PRF-secure; if either input is weak, the output is weak).
    //
    // NEW: HKDF-Extract(salt=transcript_hash_ext, ikm=transcript_hash)
    //      When ext=[0u8;32], this is HKDF-Extract(salt=0^32, ikm=internal_hash),
    //      which is still a secure PRF operation — the output is indistinguishable
    //      from random given a secure internal hash. When ext is non-zero (P2P flow),
    //      it provides genuine transcript binding.
    let combined_transcript: [u8; 32] = {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(transcript_hash_ext), &transcript_hash);
        let mut out = [0u8; 32];
        hk.expand(b"SibnaX3DH_TranscriptBind_v3", &mut out)
            .expect("HKDF expand 32 bytes always succeeds");
        out
    };

    // Derive shared secret
    #[cfg(not(feature = "pqc"))]
    let shared_secret = X3dhKdf::derive_shared_secret(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|d| d.as_bytes()),
        &combined_transcript, // use HKDF-combined transcript
    )?;

    #[cfg(feature = "pqc")]
    let (shared_secret, pq_ct) = if let Some(pk_vec) = peer_pq_pk {
        use fips203::ml_kem_768;
        use fips203::traits::{SerDes, Encaps};

        let pk_arr: [u8; 1184] = pk_vec.as_slice().try_into().map_err(|_| ProtocolError::InvalidKeyLength)?;
        let pk = ml_kem_768::EncapsKey::try_from_bytes(pk_arr)
            .map_err(|_| ProtocolError::InvalidKey)?;
        
        let (ss, ct) = <ml_kem_768::EncapsKey as Encaps>::try_encaps(&pk).map_err(|_| ProtocolError::KeyDerivationFailed)?;
        
        let ss_bytes: [u8; 32] = SerDes::into_bytes(ss);
        let derived = X3dhKdf::derive_pq_shared_secret(
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
            dh4.as_ref().map(|d| d.as_bytes()),
            &ss_bytes,
            &transcript_hash,
        )?;
        
        (derived, Some(SerDes::into_bytes(ct).to_vec()))
    } else {
        let derived = X3dhKdf::derive_shared_secret(
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
            dh4.as_ref().map(|d| d.as_bytes()),
            &transcript_hash,
        )?;
        (derived, None)
    };

    let mut result = X3dhResult::new(*shared_secret, dh_results);
    #[cfg(feature = "pqc")]
    if let Some(ct) = pq_ct {
        result = result.with_pq_ciphertext(ct);
    }
    result.validate()?;

    Ok(result)
}

/// Perform X3DH key agreement (responder)
///
/// # Arguments
/// * `our_identity` - Our identity secret key
/// * `our_signed_prekey` - Our signed prekey secret key
/// * `our_onetime_prekey` - Our one-time prekey secret key (optional)
/// * `peer_identity` - Peer's identity public key
/// * `peer_ephemeral` - Peer's ephemeral public key
/// * `our_pq_sk` - Our PQ secret key (optional, ML-KEM-768)
/// * `peer_pq_ct` - Peer's PQ ciphertext (optional, ML-KEM-768)
///
/// # Returns
/// X3DH result containing shared secret
pub fn x3dh_responder_v3(
    our_identity: &StaticSecret,
    our_signed_prekey: &StaticSecret,
    our_onetime_prekey: Option<&StaticSecret>,
    peer_identity: &PublicKey,
    peer_ephemeral: &PublicKey,
    #[cfg(feature = "pqc")]
    our_pq_sk: Option<&Vec<u8>>,
    #[cfg(feature = "pqc")]
    peer_pq_ct: Option<&Vec<u8>>,
    our_device_id: &[u8; 16],
    peer_device_id: &[u8; 16],
    transcript_hash_ext: &[u8; 32],
) -> ProtocolResult<X3dhResult> {
    // DH1: Our signed prekey + peer's identity
    let dh1 = our_signed_prekey.diffie_hellman(peer_identity);

    // DH2: Our identity + peer's ephemeral
    let dh2 = our_identity.diffie_hellman(peer_ephemeral);

    // DH3: Our signed prekey + peer's ephemeral
    let dh3 = our_signed_prekey.diffie_hellman(peer_ephemeral);

    // DH4: Our one-time prekey + peer's ephemeral (if available)
    let dh4 = our_onetime_prekey.map(|opk| {
        opk.diffie_hellman(peer_ephemeral)
    });

    // Collect DH results
    let mut dh_results = vec![
        dh1.to_bytes(),
        dh2.to_bytes(),
        dh3.to_bytes(),
    ];

    if let Some(ref dh4) = dh4 {
        dh_results.push(dh4.to_bytes());
    }

    // Derive transcript hash 
    // IMPORTANT: Only hash PUBLIC key material to ensure consistency and prevent leakage.
    let mut hasher = blake3::Hasher::new();
    hasher.update(peer_identity.as_bytes());
    hasher.update(peer_ephemeral.as_bytes());
    hasher.update(PublicKey::from(our_identity).as_bytes());
    hasher.update(PublicKey::from(our_signed_prekey).as_bytes());
    if let Some(prekey) = our_onetime_prekey {
        hasher.update(PublicKey::from(prekey).as_bytes());
    }
    hasher.update(our_device_id);
    hasher.update(peer_device_id);
    let transcript_hash: [u8; 32] = hasher.finalize().into();

    // HKDF-based transcript binding (same as initiator — see x3dh_initiator_v3)
    let combined_transcript: [u8; 32] = {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(transcript_hash_ext), &transcript_hash);
        let mut out = [0u8; 32];
        hk.expand(b"SibnaX3DH_TranscriptBind_v3", &mut out)
            .expect("HKDF expand 32 bytes always succeeds");
        out
    };

    // Derive shared secret
    #[cfg(not(feature = "pqc"))]
    let shared_secret = X3dhKdf::derive_shared_secret(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|d| d.as_bytes()),
        &combined_transcript, // use HKDF-combined transcript
    )?;

    #[cfg(feature = "pqc")]
    let shared_secret = if let (Some(sk_vec), Some(ct_vec)) = (our_pq_sk, peer_pq_ct) {
        use fips203::ml_kem_768;
        use fips203::traits::{SerDes, Decaps};

        let sk_arr: [u8; 2400] = sk_vec.as_slice().try_into().map_err(|_| ProtocolError::InvalidKeyLength)?;
        let ct_arr: [u8; 1088] = ct_vec.as_slice().try_into().map_err(|_| ProtocolError::InvalidCiphertext)?;
        
        let sk = ml_kem_768::DecapsKey::try_from_bytes(sk_arr)
            .map_err(|_| ProtocolError::InvalidKey)?;
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr)
            .map_err(|_| ProtocolError::InvalidCiphertext)?;
        
        let ss = <ml_kem_768::DecapsKey as Decaps>::try_decaps(&sk, &ct).map_err(|_| ProtocolError::KeyDerivationFailed)?;
        let ss_bytes: [u8; 32] = SerDes::into_bytes(ss);

        X3dhKdf::derive_pq_shared_secret(
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
            dh4.as_ref().map(|d| d.as_bytes()),
            &ss_bytes,
            &transcript_hash,
        )?
    } else {
        X3dhKdf::derive_shared_secret(
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
            dh4.as_ref().map(|d| d.as_bytes()),
            &transcript_hash,
        )?
    };

    let result = X3dhResult::new(*shared_secret, dh_results);
    result.validate()?;

    Ok(result)
}

/// Verify that two X3DH results produce the same shared secret
///
/// # Security
/// Uses constant-time comparison to prevent timing attacks
pub fn verify_shared_secret(a: &X3dhResult, b: &X3dhResult) -> bool {
    constant_time_eq(&a.shared_secret, &b.shared_secret)
}

/// X3DH session keys derived from shared secret
#[derive(Clone, Debug)]
pub struct X3dhSessionKeys {
    /// Encryption key for sending
    pub sending_key: [u8; 32],
    /// Encryption key for receiving
    pub receiving_key: [u8; 32],
    /// Authentication key
    pub auth_key: [u8; 32],
    /// Additional keys for future use
    pub extra_keys: Vec<[u8; 32]>,
}

impl X3dhSessionKeys {
    /// Derive session keys from shared secret
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> ProtocolResult<Self> {
        use crate::crypto::kdf::HkdfKdf;

        let infos: &[&[u8]] = &[
            // NOTE: _v3 suffix is part of the on-wire format.
            // Changing these breaks interoperability — bump to v4 if you change the format.
            b"SibnaSendingKey_v3",
            b"SibnaReceivingKey_v3",
            b"SibnaAuthKey_v3",
            b"SibnaExtraKey1_v3",
            b"SibnaExtraKey2_v3",
        ];

        // Use a proper domain-separation salt instead of empty slice
        let keys = HkdfKdf::derive_multiple(shared_secret, b"SibnaX3DH_SessionKeys_v3", infos)?;

        if keys.len() < 3 {
            return Err(ProtocolError::KeyDerivationFailed);
        }

        let sending_key = keys[0].as_slice().try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;
        let receiving_key = keys[1].as_slice().try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;
        let auth_key = keys[2].as_slice().try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;

        let extra_keys: ProtocolResult<Vec<[u8; 32]>> = keys[3..].iter()
            .map(|k| k.as_slice().try_into().map_err(|_| ProtocolError::InvalidKeyLength))
            .collect();
        let extra_keys = extra_keys?;

        Ok(Self {
            sending_key,
            receiving_key,
            auth_key,
            extra_keys,
        })
    }
}

impl Zeroize for X3dhSessionKeys {
    fn zeroize(&mut self) {
        self.sending_key.zeroize();
        self.receiving_key.zeroize();
        self.auth_key.zeroize();
        for key in &mut self.extra_keys {
            key.zeroize();
        }
    }
}

impl ZeroizeOnDrop for X3dhSessionKeys {}

impl Drop for X3dhSessionKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{X3dhKdf};
    use rand_core::OsRng;

    #[test]
    fn test_x3dh_kdf_direct() {
        let dh1 = [0x01u8; 32];
        let dh2 = [0x02u8; 32];
        let dh3 = [0x03u8; 32];
        let hash = [0xAAu8; 32];
        
        let secret1 = X3dhKdf::derive_shared_secret(&dh1, &dh2, &dh3, None, &hash).unwrap();
        let secret2 = X3dhKdf::derive_shared_secret(&dh1, &dh2, &dh3, None, &hash).unwrap();
        assert_eq!(secret1.as_ref(), secret2.as_ref());

        let hash2 = [0xBBu8; 32];
        let secret3 = X3dhKdf::derive_shared_secret(&dh1, &dh2, &dh3, None, &hash2).unwrap();
        assert_ne!(secret1.as_ref(), secret3.as_ref());
    }

    #[test]
    fn test_x3dh_initiator_responder_full() {
        // Generate keys for party A
        let a_identity = StaticSecret::random_from_rng(&mut OsRng);
        let a_identity_public = PublicKey::from(&a_identity);
        let a_ephemeral = StaticSecret::random_from_rng(&mut OsRng);
        let a_ephemeral_public = PublicKey::from(&a_ephemeral);

        // Generate keys for party B
        let b_identity = StaticSecret::random_from_rng(&mut OsRng);
        let b_identity_public = PublicKey::from(&b_identity);
        let b_signed_prekey = StaticSecret::random_from_rng(&mut OsRng);
        let b_signed_prekey_public = PublicKey::from(&b_signed_prekey);
        let b_onetime_prekey = StaticSecret::random_from_rng(&mut OsRng);
        let b_onetime_prekey_public = PublicKey::from(&b_onetime_prekey);

        // A performs initiator handshake
        #[cfg(not(feature = "pqc"))]
        let result_a = x3dh_initiator_v3(
            &a_identity,
            &a_ephemeral,
            &b_identity_public,
            &b_signed_prekey_public,
            Some(&b_onetime_prekey_public),
            &[0u8; 16],
            &[0u8; 16],
            &[0u8; 32],
        ).unwrap();

        #[cfg(feature = "pqc")]
        let result_a = x3dh_initiator_v3(
            &a_identity,
            &a_ephemeral,
            &b_identity_public,
            &b_signed_prekey_public,
            Some(&b_onetime_prekey_public),
            None,
            &[0u8; 16],
            &[0u8; 16],
            &[0u8; 32],
        ).unwrap();

        // B performs responder handshake
        #[cfg(not(feature = "pqc"))]
        let result_b = x3dh_responder_v3(
            &b_identity,
            &b_signed_prekey,
            Some(&b_onetime_prekey),
            &a_identity_public,
            &a_ephemeral_public,
            &[0u8; 16],
            &[0u8; 16],
            &[0u8; 32],
        ).unwrap();

        #[cfg(feature = "pqc")]
        let result_b = x3dh_responder_v3(
            &b_identity,
            &b_signed_prekey,
            Some(&b_onetime_prekey),
            &a_identity_public,
            &a_ephemeral_public,
            None,
            None,
            &[0u8; 16],
            &[0u8; 16],
            &[0u8; 32],
        ).unwrap();

        // Shared secrets should match
        assert!(verify_shared_secret(&result_a, &result_b));
    }

    #[test]
    #[cfg(feature = "pqc")]
    fn test_pq_x3dh_hybrid_full() {
        use fips203::ml_kem_768;
        use fips203::traits::{KeyGen, SerDes};

        // Generate keys for party A
        let a_identity = StaticSecret::random_from_rng(&mut OsRng);
        let a_identity_public = PublicKey::from(&a_identity);
        let a_ephemeral = StaticSecret::random_from_rng(&mut OsRng);
        let a_ephemeral_public = PublicKey::from(&a_ephemeral);

        // Generate keys for party B (including PQC)
        let b_identity = StaticSecret::random_from_rng(&mut OsRng);
        let b_identity_public = PublicKey::from(&b_identity);
        let b_signed_prekey = StaticSecret::random_from_rng(&mut OsRng);
        let b_signed_prekey_public = PublicKey::from(&b_signed_prekey);
        
        let (pq_pk, pq_sk) = ml_kem_768::KG::try_keygen().unwrap();
        let pq_pk_bytes = SerDes::into_bytes(pq_pk).to_vec();
        let pq_sk_bytes = SerDes::into_bytes(pq_sk).to_vec();

        // A performs initiator handshake with PQC
        let result_a = x3dh_initiator_v3(
            &a_identity,
            &a_ephemeral,
            &b_identity_public,
            &b_signed_prekey_public,
            None,
            Some(&pq_pk_bytes),
            &[0u8; 16],
            &[0u8; 16],
            &[0u8; 32],
        ).unwrap();

        assert!(result_a.pq_ciphertext.is_some());
        let ct = result_a.pq_ciphertext.clone().unwrap();

        // B performs responder handshake with PQC
        let result_b = x3dh_responder_v3(
            &b_identity,
            &b_signed_prekey,
            None,
            &a_identity_public,
            &a_ephemeral_public,
            Some(&pq_sk_bytes),
            Some(&ct),
            &[0u8; 16],
            &[0u8; 16],
            &[0u8; 32],
        ).unwrap();

        // Shared secrets should match
        assert!(verify_shared_secret(&result_a, &result_b));
    }
}
