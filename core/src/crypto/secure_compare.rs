//! Constant-time comparison primitives.

use subtle::{ConstantTimeEq, Choice, ConditionallySelectable};

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

pub fn constant_time_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.ct_eq(b).into()
}

pub fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.ct_eq(b).into()
}

pub fn constant_time_eq_48(a: &[u8; 48], b: &[u8; 48]) -> bool {
    a.ct_eq(b).into()
}

pub fn constant_time_select(condition: bool, a: u8, b: u8) -> u8 {
    let mut val = b;
    val.conditional_assign(&a, Choice::from(condition as u8));
    val
}

pub fn constant_time_copy(condition: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    let choice = Choice::from(condition as u8);
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        d.conditional_assign(s, choice);
    }
}

pub fn constant_time_is_zero(slice: &[u8]) -> bool {
    slice.ct_eq(&vec![0u8; slice.len()]).into()
}

pub fn constant_time_contains(slice: &[u8], target: u8) -> bool {
    let mut found = Choice::from(0);
    for &byte in slice {
        found |= byte.ct_eq(&target);
    }
    found.into()
}

/// Returns 0 if equal, 1 if not, -1 if lengths differ.
pub fn constant_time_memcmp(a: &[u8], b: &[u8]) -> i32 {
    if a.len() != b.len() { return -1; }
    if a.ct_eq(b).into() { 0 } else { 1 }
}

pub fn secure_zero(memory: &mut [u8]) {
    use zeroize::Zeroize;
    memory.zeroize();
}

pub fn verify_hmac(key: &[u8], data: &[u8], mac: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut h = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    h.update(data);
    h.finalize().into_bytes().ct_eq(mac).into()
}

/// Compare two equal-length byte slices in constant time.
///
/// Not a password verifier — input must already be KDF output (e.g. two HMAC tags).
/// For password login, use `argon2::verify_encoded` instead.
pub fn secure_password_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub fn batch_constant_time_compare(value: &[u8], candidates: &[&[u8]]) -> Option<usize> {
    let mut match_index = u32::MAX;
    let mut found = Choice::from(0);
    for (i, candidate) in candidates.iter().enumerate() {
        let is_match = value.ct_eq(candidate);
        let update = (!found) & is_match;
        match_index.conditional_assign(&(i as u32), update);
        found |= is_match;
    }
    if found.into() { Some(match_index as usize) } else { None }
}

/// Lexicographic ordering for non-sensitive data (e.g. deterministic role assignment).
/// Not constant-time — never use on secrets.
#[doc(hidden)]
pub(crate) fn lexicographic_order_non_sensitive(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.cmp(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_and_neq() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
    }

    #[test]
    fn batch_compare() {
        let candidates: &[&[u8]] = &[b"wrong", b"secret", b"other"];
        assert_eq!(batch_constant_time_compare(b"secret", candidates), Some(1));
        assert_eq!(batch_constant_time_compare(b"missing", candidates), None);
    }
}
