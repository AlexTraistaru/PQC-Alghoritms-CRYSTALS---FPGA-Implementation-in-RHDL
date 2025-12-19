use crate::dilithium_params::Q;

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
