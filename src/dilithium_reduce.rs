use crate::dilithium_params::{Q, QINV};

// Keep values in a reasonable range (not constant-time hardened).
#[inline]
pub fn mod_q(mut x: i64) -> i32 {
    let q = Q as i64;
    x %= q;
    if x < 0 { x += q; }
    x as i32
}

#[inline]
pub fn caddq(a: i32) -> i32 {
    let mut r = a;
    if r < 0 { r += Q; }
    r
}

#[inline]
pub fn csubq(a: i32) -> i32 {
    let mut r = a;
    if r >= Q { r -= Q; }
    r
}

#[inline]
pub fn add_mod(a: i32, b: i32) -> i32 {
    csubq(caddq(a + b))
}

#[inline]
pub fn sub_mod(a: i32, b: i32) -> i32 {
    caddq(a - b)
}

#[inline]
pub fn mul_mod(a: i32, b: i32) -> i32 {
    mod_q((a as i64) * (b as i64))
}

// -----------------------------------------------------------------------------
// Montgomery multiplication (software)
//
// Dilithium's NTT/pointwise multiplication uses Montgomery arithmetic with
// R = 2^32.
//
// If a and b are in Montgomery form (aR mod q, bR mod q), then
//   mont_fqmul(a, b) = (a * b * R^{-1}) mod q
// which yields a result also in Montgomery form.

/// Software Montgomery reduction for q=8380417, QINV = -q^{-1} mod 2^32.
#[inline(always)]
pub fn montgomery_reduce(a: i64) -> i32 {
    // Match the reference's 32-bit behavior:
    // t = (int32_t)a * QINV;  // low 32 bits
    // t = (a - (int64_t)t*Q) >> 32;
    //
    // We compute in i128 to avoid any UB/overflow.
    let a128 = a as i128;
    let t = ((a as i32 as i64) * (QINV as i64)) as i32; // implicit low-32bit wrap
    let t128 = t as i128;
    let r = (a128 - t128 * (Q as i128)) >> 32;
    r as i32
}

/// Montgomery multiplication (fqmul) for NTT-domain coefficients.
#[inline(always)]
pub fn mont_fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce((a as i64) * (b as i64))
}
