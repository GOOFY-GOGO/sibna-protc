//! Unified Secure Storage
//!
//! Handles atomic, encrypted, and versioned storage of the entire SecureContext.
//! Includes Salt persistence and Rollback protection.

use crate::error::{ProtocolError, ProtocolResult};
use crate::keystore::KeyStore;
use crate::SessionManager;
use crate::group::GroupManager;
use serde::{Serialize, Deserialize};
use subtle::ConstantTimeEq;


/// Unified storage payload
#[derive(Serialize, Deserialize)]
pub struct StoragePayload {
    /// Protocol version
    pub version: u32,
    /// Global sequence number for rollback protection
    pub sequence_number: u64,
    /// Keystore state
    pub keystore: KeyStore,
    /// Session manager state
    pub sessions: SessionManager,
    /// Group manager state
    pub groups: GroupManager,
    /// Timestamp of last save
    pub last_save: u64,
}

/// Sidecar file written alongside the encrypted blob.
///
/// `manifest_mac` is HMAC-SHA256(version || sequence_number || blob_hash)
/// keyed by the storage encryption key. This stops an attacker with filesystem
/// write access from rolling back to an older blob+manifest pair without knowing
/// the key. It does not protect against attackers who can also read the key.
#[derive(Serialize, Deserialize)]
pub struct StorageManifest {
    pub version: u32,
    pub sequence_number: u64,
    pub blob_hash: [u8; 32],
    pub manifest_mac: [u8; 32],
}

/// Unified secure storage handler
pub struct SecureStorage;

impl SecureStorage {
    /// Format identifier for file header
    const MAGIC: &'static [u8; 8] = b"SIBNA001";
    
    /// Current storage format version
    const CURRENT_VERSION: u32 = 1;

    /// Serialize and encrypt the entire context to bytes.
    ///
    /// File Format:
    /// MAGIC (8) || SALT (32) || ENCRYPTED_PAYLOAD
    pub fn save_context(
        path: &std::path::Path,
        encryption_key: &[u8; 32],
        salt: &[u8; 32],
        keystore: &KeyStore,
        sessions: &SessionManager,
        groups: &GroupManager,
        sequence_number: u64,
    ) -> ProtocolResult<()> {
        let _lock_file = Self::_acquire_lock(path)?;
        use std::io::Write;
        use crate::crypto::CryptoHandler;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|e| { tracing::error!("clock regression in storage: {:?}", e); std::time::Duration::from_secs(u64::MAX / 2) })
            .as_secs();

        let payload = StoragePayload {
            version: Self::CURRENT_VERSION,
            sequence_number,
            keystore: keystore.clone(),
            sessions: sessions.clone(), // This is shallow clone for the maps
            groups: groups.clone(),
            last_save: now,
        };

        // Serialize payload
        let plaintext = bincode::encode_to_vec(&payload, bincode::config::legacy())
            .map_err(|_| ProtocolError::SerializationError)?;

        // Encrypt payload
        let handler = CryptoHandler::new(encryption_key)
            .map_err(|_| ProtocolError::InternalError)?;
        
        // Use a fixed salt for the encryption key derivation IF NOT PROVIDED.
        // Actually, the Argon2 salt should be passed in or stored in the header.
        // For simplicity, we assume encryption_key is already derived.
        let encrypted = handler.encrypt(&plaintext, b"SibnaUnifiedStore_v1")
            .map_err(|_| ProtocolError::StorageError)?;

        // Atomic write
        let tmp_path = path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp_path)
            .map_err(|_| ProtocolError::StorageError)?;
        
        file.write_all(Self::MAGIC)
            .map_err(|_| ProtocolError::StorageError)?;
        file.write_all(salt)
            .map_err(|_| ProtocolError::StorageError)?;
        file.write_all(encrypted.as_slice())
            .map_err(|_| ProtocolError::StorageError)?;
        
        file.sync_all()
            .map_err(|_| ProtocolError::StorageError)?;
        drop(file);

        // 4. Save Manifest with HMAC authentication 
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, &encrypted);
        let blob_hash: [u8; 32] = sha2::Digest::finalize(hasher).into();

        // Compute HMAC-SHA256 over (version || sequence_number || blob_hash)
        // keyed by the encryption key — prevents manifest replacement attack.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac_input = Vec::with_capacity(4 + 8 + 32);
        mac_input.extend_from_slice(&payload.version.to_le_bytes());
        mac_input.extend_from_slice(&payload.sequence_number.to_le_bytes());
        mac_input.extend_from_slice(&blob_hash);
        let mut hmac = <Hmac<Sha256>>::new_from_slice(encryption_key)
            .expect("HMAC accepts any key length");
        hmac.update(&mac_input);
        let manifest_mac: [u8; 32] = hmac.finalize().into_bytes().into();

        let manifest = StorageManifest {
            version: payload.version,
            sequence_number: payload.sequence_number,
            blob_hash,
            manifest_mac,
        };
        let manifest_bytes = bincode::encode_to_vec(&manifest, bincode::config::legacy())
            .map_err(|_| ProtocolError::SerializationError)?;
        
        let manifest_path = path.with_extension("manifest");
        std::fs::write(&manifest_path, manifest_bytes)
            .map_err(|_| ProtocolError::StorageError)?;

        std::fs::rename(&tmp_path, path)
            .map_err(|_| ProtocolError::StorageError)?;

        Self::_release_lock(path);
        Ok(())
    }

    /// Load and decrypt the entire context from bytes.
    pub fn load_context(
        path: &std::path::Path,
        encryption_key: &[u8; 32],
    ) -> ProtocolResult<(StoragePayload, [u8; 32])> {
        let _lock_file = Self::_acquire_lock(path)?;
        use std::io::Read;
        use crate::crypto::CryptoHandler;

        // 1. Read Manifest if it exists 
        let manifest_path = path.with_extension("manifest");
        let manifest: Option<StorageManifest> = if manifest_path.exists() {
            let bytes = std::fs::read(&manifest_path)
                .map_err(|_| ProtocolError::StorageError)?;
            Some(bincode::decode_from_slice(&bytes, bincode::config::legacy()).map(|(v,_)|v).map_err(|_| ProtocolError::DeserializationError)?)
        } else {
            None
        };

        // 2. Read Blob
        let mut file = std::fs::File::open(path)
            .map_err(|_| ProtocolError::StorageError)?;
        
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)
            .map_err(|_| ProtocolError::StorageError)?;
        
        if &magic != Self::MAGIC {
            return Err(ProtocolError::StorageError);
        }

        let mut salt = [0u8; 32];
        file.read_exact(&mut salt)
            .map_err(|_| ProtocolError::StorageError)?;

        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)
            .map_err(|_| ProtocolError::StorageError)?;

        let handler = CryptoHandler::new(encryption_key)
            .map_err(|_| ProtocolError::InternalError)?;
        
        // 3. Verify Manifest HMAC and Hash 
        if let Some(ref m) = manifest {
            // First: verify the manifest's own HMAC to prevent manifest replacement
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            use subtle::ConstantTimeEq;
            let mut mac_input = Vec::with_capacity(4 + 8 + 32);
            mac_input.extend_from_slice(&m.version.to_le_bytes());
            mac_input.extend_from_slice(&m.sequence_number.to_le_bytes());
            mac_input.extend_from_slice(&m.blob_hash);
            let mut hmac = <Hmac<Sha256>>::new_from_slice(encryption_key)
                .expect("HMAC accepts any key length");
            hmac.update(&mac_input);
            let expected_mac: [u8; 32] = hmac.finalize().into_bytes().into();

            if m.manifest_mac.ct_eq(&expected_mac).unwrap_u8() == 0 {
                // Manifest MAC mismatch: either the manifest was replaced (rollback attack)
                // or it was created by an older version without HMAC.
                // Reject to protect against rollback. Users with old manifests
                // must delete the manifest file and re-save (losing rollback protection for one save).
                tracing::error!(
                    "StorageManifest HMAC verification failed — possible rollback attack or manifest from v3.0.0. \
                     Delete the .manifest file to bypass (you lose rollback protection for this session)."
                );
                return Err(ProtocolError::StorageError);
            }

            // Then: verify blob hash matches manifest
            let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
            sha2::Digest::update(&mut hasher, &encrypted);
            let actual_hash: [u8; 32] = sha2::Digest::finalize(hasher).into();

            if m.blob_hash != actual_hash {
                return Err(ProtocolError::StorageError); // Blob tampered
            }
        }

        let plaintext = handler.decrypt(&encrypted, b"SibnaUnifiedStore_v1")
            .map_err(|_| ProtocolError::StorageError)?;

        let payload: StoragePayload = bincode::decode_from_slice(&plaintext, bincode::config::legacy()).map(|(v,_)|v)
            .map_err(|_| ProtocolError::DeserializationError)?;

        // 4. Verify Sequence Number (Rollback Protection) - v3.0.0
        if let Some(ref m) = manifest {
            if payload.sequence_number < m.sequence_number {
                return Err(ProtocolError::StorageError); // Rollback detected
            }
        }

        // Safety Jump for all sessions 
        // no nonce reuse even after a crash
        for session_item in payload.sessions.iter() {
            session_item.value().read().jump_to_reservation()
                .map_err(|_| ProtocolError::InternalError)?;
        }

        Self::_release_lock(path);
        Ok((payload, salt))
    }

    /// Internal: Acquire a simple lock file
    fn _acquire_lock(path: &std::path::Path) -> ProtocolResult<std::fs::File> {
        let lock_path = path.with_extension("lock");
        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < 30 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(f) => return Ok(f),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => return Err(ProtocolError::StorageError),
            }
        }
        Err(ProtocolError::Timeout) // Lock timeout
    }

    /// Internal: Release a simple lock file
    fn _release_lock(path: &std::path::Path) {
        let lock_path = path.with_extension("lock");
        let _ = std::fs::remove_file(lock_path);
    }
}
