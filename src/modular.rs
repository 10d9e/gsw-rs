//! Modular arithmetic utilities for Z_q.

/// Reduce value to range [0, q) for unsigned modulus.
#[inline]
pub fn mod_q(val: i64, q: u64) -> u64 {
    let q = q as i64;
    let mut r = val % q;
    if r < 0 {
        r += q;
    }
    r as u64
}

/// Reduce value to range (-q/2, q/2] for centered modulus (used in decryption).
#[inline]
pub fn mod_q_centered(val: i64, q: u64) -> i64 {
    let q = q as i64;
    let mut r = val % q;
    if r > q / 2 {
        r -= q;
    } else if r <= -q / 2 {
        r += q;
    }
    r
}
