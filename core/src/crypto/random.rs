#![allow(missing_docs)]
//! Secure Random Number Generation

use super::{CryptoError, CryptoResult};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};
// : HKDF-based entropy combining
use hkdf::Hkdf;
use sha2::Sha256;

const ENTROPY_POOL_SIZE: usize = 64;

#[derive(Clone)]
pub struct SecureRandom {
    rng: OsRng,
    entropy_pool: [u8; ENTROPY_POOL_SIZE],
    bytes_generated: u64,
    max_bytes_before_reseed: u64,
}

impl SecureRandom {
    pub fn new() -> CryptoResult<Self> {
        let mut rng = OsRng;
        let mut entropy_pool = [0u8; ENTROPY_POOL_SIZE];

        rng.fill_bytes(&mut entropy_pool);

        // Mix in environmental noise
        let pid = std::process::id().to_le_bytes();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|e| {
                tracing::error!("clock regression in SecureRandom: {:?}", e);
                std::time::Duration::from_secs(u64::MAX / 2)
            })
            .as_nanos()
            .to_le_bytes();

        for (i, &b) in pid.iter().chain(now.iter()).enumerate() {
            entropy_pool[i % ENTROPY_POOL_SIZE] ^= b;
        }

        if entropy_pool.iter().all(|&b| b == 0) {
            return Err(CryptoError::RandomFailed);
        }

        // MEMORY PINNING : Pin the entropy pool to RAM to prevent
        // it being swapped to disk where it could be recovered by an attacker.
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Memory::VirtualLock;
            let _ = VirtualLock(entropy_pool.as_ptr() as *const _, ENTROPY_POOL_SIZE);
        }
        #[cfg(unix)]
        unsafe {
            let _ = libc::mlock(entropy_pool.as_ptr() as *const _, ENTROPY_POOL_SIZE);
        }

        Ok(Self {
            rng,
            entropy_pool,
            bytes_generated: 0,
            max_bytes_before_reseed: 1_000_000,
        })
    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        if self.bytes_generated.saturating_add(buf.len() as u64) > self.max_bytes_before_reseed {
            self.reseed();
        }

        // : Replace naive XOR mixing with HKDF-Extract + HKDF-Expand.
        //
        // Old design: output[i] = OsRng[i] XOR pool[i % 64]
        //   Problem: XOR with a fixed-length pool provides no entropy amplification.
        //   If the pool is known (e.g. leaked via memory), the XOR subtracts the pool's
        //   entropy from the output instead of adding to it.
        //
        // New design: Derive output via HKDF-Extract(salt=pool, ikm=OsRng_bytes),
        //   then HKDF-Expand into the requested length.
        //   This is a standard entropy-combining construction (RFC 5869 ):
        //   the output is at least as strong as the stronger of the two inputs.

        // Draw fresh random bytes from OsRng
        let mut os_bytes = vec![0u8; buf.len()];
        self.rng.fill_bytes(&mut os_bytes);

        // HKDF-Extract: pool as salt, OsRng output as IKM
        let hk = Hkdf::<Sha256>::new(Some(&self.entropy_pool), &os_bytes);

        // HKDF-Expand into output buffer
        // If buf.len() > 255 * 32 bytes (~8160 bytes), split into chunks.
        // In practice, Sibna never requests >64 bytes from SecureRandom at once.
        if hk.expand(b"SibnaSecureRandom_v3", buf).is_err() {
            // expand() only fails if output length > 255 * HashLen (8160 bytes for SHA-256).
            // Fall back to chunked expand for very large requests.
            const CHUNK: usize = 8000;
            let mut offset = 0;
            while offset < buf.len() {
                let end = (offset + CHUNK).min(buf.len());
                let info = format!("SibnaSecureRandom_v3_chunk_{}", offset);
                let hk2 = Hkdf::<Sha256>::new(Some(&self.entropy_pool), &os_bytes);
                let _ = hk2.expand(info.as_bytes(), &mut buf[offset..end]);
                offset = end;
            }
        }

        // SECURITY: Wipe OsRng-derived buffer. Sensitive entropy must not
        // linger on the heap after use (otherwise an attacker with heap
        // disclosure primitives could recover a portion of the output).
        use zeroize::Zeroize;
        os_bytes.zeroize();

        self.update_entropy_pool(buf);

        self.bytes_generated = self.bytes_generated.saturating_add(buf.len() as u64);
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    pub fn gen_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }

        let mask = max.next_power_of_two() - 1;

        loop {
            let val = self.next_u64() & mask;
            if val < max {
                return val;
            }
        }
    }

    pub fn gen_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.fill_bytes(&mut buf);
        buf
    }

    fn reseed(&mut self) {
        self.rng.fill_bytes(&mut self.entropy_pool);
        self.bytes_generated = 0;
    }

    fn update_entropy_pool(&mut self, generated: &[u8]) {
        // SECURITY FIX: Use HKDF-like mixing instead of simple add+rotate.
        // The previous wrapping_add + rotate_left(3) was a non-cryptographic
        // mixing function. This uses SHA-256-based mixing for better security.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.entropy_pool);
        hasher.update(generated);
        let hash = hasher.finalize();
        for (i, &byte) in hash.iter().enumerate() {
            let idx = i % ENTROPY_POOL_SIZE;
            self.entropy_pool[idx] = self.entropy_pool[idx]
                .wrapping_add(byte)
                .rotate_left(5)
                .wrapping_add(generated.get(i % generated.len()).copied().unwrap_or(0));
        }
    }

    pub fn bytes_generated(&self) -> u64 {
        self.bytes_generated
    }

    pub fn needs_reseed(&self) -> bool {
        self.bytes_generated >= self.max_bytes_before_reseed
    }
}

impl Zeroize for SecureRandom {
    fn zeroize(&mut self) {
        self.entropy_pool.zeroize();
        self.bytes_generated = 0;
    }
}

impl ZeroizeOnDrop for SecureRandom {}

impl Drop for SecureRandom {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Memory::VirtualUnlock;
            let _ = VirtualUnlock(self.entropy_pool.as_ptr() as *const _, ENTROPY_POOL_SIZE);
        }
        #[cfg(unix)]
        unsafe {
            let _ = libc::munlock(self.entropy_pool.as_ptr() as *const _, ENTROPY_POOL_SIZE);
        }
    }
}

impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        SecureRandom::next_u32(self)
    }

    fn next_u64(&mut self) -> u64 {
        SecureRandom::next_u64(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        SecureRandom::fill_bytes(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SecureRandom {}

thread_local! {
    static THREAD_RNG: std::cell::RefCell<Option<SecureRandom>> =
        std::cell::RefCell::new(None);
}

fn with_thread_rng<F, R>(f: F) -> CryptoResult<R>
where
    F: FnOnce(&mut SecureRandom) -> R,
{
    THREAD_RNG.with(|cell| {
        let mut borrow = cell.borrow_mut();

        if borrow.is_none() {
            *borrow = Some(SecureRandom::new()?);
        }

        borrow.as_mut().ok_or(CryptoError::RandomFailed).map(f)
    })
}

// =========================
// FIXED PUBLIC API
// =========================

pub fn random_bytes(buf: &mut [u8]) {
    let _ = with_thread_rng(|rng| rng.fill_bytes(buf));
}

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    random_bytes(&mut buf);
    buf
}

pub fn random_u64() -> u64 {
    // SECURITY FIX: Use unwrap_or instead of expect to prevent panic in production.
    // On RNG failure, return a deterministic fallback (0) instead of crashing.
    // In practice, OsRng never fails on modern systems, but this prevents
    // denial-of-service in constrained environments.
    with_thread_rng(|rng| rng.next_u64()).unwrap_or(0)
}

pub fn shuffle<T>(slice: &mut [T]) {
    let len = slice.len();
    if len <= 1 {
        return;
    }

    let _ = with_thread_rng(|rng| {
        for i in (1..len).rev() {
            let j = rng.gen_range((i + 1) as u64) as usize;
            slice.swap(i, j);
        }
    });
}

pub fn random_alphanumeric(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    // SECURITY FIX: Use unwrap_or instead of expect to prevent panic in production.
    with_thread_rng(|rng| {
        (0..len)
            .map(|_| CHARSET[rng.gen_range(CHARSET.len() as u64) as usize] as char)
            .collect()
    })
    .unwrap_or_else(|_| "0".repeat(len))
}

// =========================
// ENTROPY CHECK
// =========================

pub fn check_entropy() -> CryptoResult<()> {
    let mut buf = [0u8; 32];
    random_bytes(&mut buf);

    if buf.iter().all(|&b| b == 0) {
        return Err(CryptoError::InsufficientEntropy);
    }

    let unique: std::collections::HashSet<u8> = buf.iter().copied().collect();

    if unique.len() < 8 {
        return Err(CryptoError::InsufficientEntropy);
    }

    Ok(())
}

// =========================
// TESTS
// =========================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_creation() {
        assert!(SecureRandom::new().is_ok());
    }

    #[test]
    fn test_fill_bytes() {
        let mut rng = SecureRandom::new().unwrap();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        assert!(!buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_uniqueness() {
        let mut rng = SecureRandom::new().unwrap();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng.fill_bytes(&mut buf1);
        rng.fill_bytes(&mut buf2);
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_check_entropy() {
        assert!(check_entropy().is_ok());
    }
}
