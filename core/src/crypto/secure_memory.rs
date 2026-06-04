//! Secure Memory Wrapper
//!
//! SIBNA-2026-017 (PATCH 21): Heap-allocated byte buffer that is **pinned
//! to physical RAM** so the OS will never swap it to disk. On Unix
//! this uses `mlock(2)`; on Windows it uses `VirtualLock` (Win32 API).
//!
//! # Threat model
//! Without locking, an attacker with post-exploitation access to the
//! swap file (or to a memory-dump primitive that scans the page file
//! or hibernation file) can recover secret material that was
//! resident in process memory. Pinning prevents the page from being
//! evicted to the swap file.
//!
//! # Limitations
//! - On Windows, `VirtualLock` is per-process. The pages are still
//!   visible to anyone with `ReadProcessMemory` against this process.
//!   Use as part of a defense-in-depth strategy.
//! - On some Unix systems, `mlock` is subject to `RLIMIT_MEMLOCK`.
//!   If the limit is too small, `mlock` returns `ENOMEM` and the
//!   memory is left **unlocked** (logged via `tracing::warn`).
//!   Callers MUST treat the buffer as best-effort secure, not as
//!   a hard guarantee.
//! - Locking is a no-op for `size == 0` buffers.
//!
//! # Drop semantics
//! On `Drop`, the memory is:
//! 1. Unlocked (so the kernel can reclaim the page after process exit).
//! 2. Zeroized in place (so the bytes don't linger in the heap).
//!
//! The type is `!Clone` to make accidental duplication hard.

#[cfg(unix)]
use libc::{mlock, munlock};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

use zeroize::Zeroize;

/// Heap-allocated, memory-locked byte buffer.
///
/// Construct with [`SecureMemory::new`] or [`SecureMemory::new_zeroed`].
/// The buffer is automatically zeroized and unlocked on drop.
pub struct SecureMemory {
    /// Heap-allocated bytes. Wrapped in `Box<[u8]>` so the address is
    /// stable for the lifetime of the struct (no realloc on growth).
    data: Box<[u8]>,
    /// Whether `mlock`/`VirtualLock` succeeded at construction time.
    /// `false` means the buffer is still heap-allocated and zeroized
    /// on drop, but is **not** pinned against swapping.
    locked: bool,
}

impl SecureMemory {
    /// Allocate a zeroed, memory-locked buffer of `size` bytes.
    pub fn new(size: usize) -> Self {
        if size == 0 {
            return Self {
                data: Box::from([]),
                locked: false,
            };
        }
        let mut data = vec![0u8; size].into_boxed_slice();
        let locked = lock_bytes(&mut data);
        Self { data, locked }
    }

    /// Allocate a memory-locked buffer initialized with `bytes`.
    /// Returns `None` if the length is zero (callers that need an
    /// empty buffer should use [`SecureMemory::new(0)`] explicitly).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut me = Self::new(bytes.len());
        me.data.copy_from_slice(bytes);
        me
    }

    /// Immutable view.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Mutable view.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True if the buffer holds zero bytes.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether the buffer is currently pinned against swap.
    /// May be `false` if `mlock`/`VirtualLock` failed at construction.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        if self.locked && !self.data.is_empty() {
            unlock_bytes(&mut self.data);
        }
        self.data.zeroize();
    }
}

impl std::fmt::Debug for SecureMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureMemory")
            .field("len", &self.data.len())
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

// SAFETY: SecureMemory owns a Box<[u8]> with stable address and no
// internal mutability. It is safe to send between threads.
unsafe impl Send for SecureMemory {}
// SAFETY: All mutation requires `&mut self`. Concurrent reads from
// `&self` (via `as_slice`) are safe because Box<[u8]> is Sync.
unsafe impl Sync for SecureMemory {}

// ── platform helpers ────────────────────────────────────────────────────

#[cfg(unix)]
fn lock_bytes(data: &mut [u8]) -> bool {
    // SAFETY: data.as_ptr() is a valid pointer to data.len() bytes
    // for the entire scope of `data`; the Box keeps the address stable.
    let rc = unsafe { mlock(data.as_ptr() as *const _, data.len()) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            "SecureMemory::mlock failed (size={}, errno={:?}): {}; \
             buffer NOT pinned against swap (SIBNA-2026-017).",
            data.len(),
            err.raw_os_error(),
            err,
        );
        false
    } else {
        true
    }
}

#[cfg(unix)]
fn unlock_bytes(data: &mut [u8]) {
    // SAFETY: same as lock_bytes.
    let rc = unsafe { munlock(data.as_ptr() as *const _, data.len()) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            "SecureMemory::munlock failed (size={}, errno={:?}): {}.",
            data.len(),
            err.raw_os_error(),
            err,
        );
    }
}

#[cfg(windows)]
fn lock_bytes(data: &mut [u8]) -> bool {
    // SAFETY: data.as_ptr() is a valid pointer to data.len() bytes
    // for the entire scope of `data`; the Box keeps the address stable.
    // VirtualLock returns nonzero (BOOL=TRUE) on success, 0 on failure.
    let ok = unsafe { VirtualLock(data.as_ptr() as *const _, data.len()) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            "SecureMemory::VirtualLock failed (size={}, err={:?}): {}; \
             buffer NOT pinned against swap (SIBNA-2026-017).",
            data.len(),
            err.raw_os_error(),
            err,
        );
        false
    } else {
        true
    }
}

#[cfg(windows)]
fn unlock_bytes(data: &mut [u8]) {
    // SAFETY: same as lock_bytes.
    let ok = unsafe { VirtualUnlock(data.as_ptr() as *const _, data.len()) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            "SecureMemory::VirtualUnlock failed (size={}, err={:?}): {}.",
            data.len(),
            err.raw_os_error(),
            err,
        );
    }
}

#[cfg(not(any(unix, windows)))]
fn lock_bytes(_data: &mut [u8]) -> bool {
    tracing::warn!(
        "SecureMemory: no platform lock primitive available; \
         buffer NOT pinned (SIBNA-2026-017)."
    );
    false
}

#[cfg(not(any(unix, windows)))]
fn unlock_bytes(_data: &mut [u8]) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_allocation_and_access() {
        let mut buf = SecureMemory::new(64);
        assert_eq!(buf.len(), 64);
        assert!(!buf.is_empty());
        // The buffer is zero-initialized.
        assert!(buf.as_slice().iter().all(|&b| b == 0));
        // Write a pattern.
        for (i, b) in buf.as_mut_slice().iter_mut().enumerate() {
            *b = i as u8;
        }
        // Read it back.
        for (i, b) in buf.as_slice().iter().enumerate() {
            assert_eq!(*b, i as u8);
        }
        // The buffer is locked (or at least constructed without panic) on
        // every supported platform. is_locked() is a best-effort signal;
        // we don't assert it must be `true` because some CI environments
        // may not permit mlock/VirtualLock for the test process.
        let _ = buf.is_locked();
    }

    #[test]
    fn from_bytes_initializes() {
        let payload = [0xABu8; 32];
        let buf = SecureMemory::from_bytes(&payload);
        assert_eq!(buf.as_slice(), &payload);
    }

    #[test]
    fn zero_sized_buffer_is_safe() {
        let buf = SecureMemory::new(0);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        // Drop must not panic; the unlock path skips empty buffers.
        drop(buf);
    }

    #[test]
    fn drop_does_not_panic() {
        // Repeatedly construct and drop. The Drop impl unlocks (if
        // locked) and zeroizes. A bug in either step would surface
        // as a panic in the second iteration (the page is no longer
        // ours after the first drop).
        for _ in 0..16 {
            let mut buf = SecureMemory::new(128);
            buf.as_mut_slice()[0] = 0xCD;
            drop(buf);
        }
    }

    #[test]
    fn debug_redacts_contents() {
        let buf = SecureMemory::from_bytes(b"super-secret-key-bytes");
        let dbg = format!("{:?}", buf);
        // Must NOT include the actual secret bytes in the Debug output.
        assert!(!dbg.contains("super-secret-key-bytes"));
        assert!(dbg.contains("SecureMemory"));
    }
}
