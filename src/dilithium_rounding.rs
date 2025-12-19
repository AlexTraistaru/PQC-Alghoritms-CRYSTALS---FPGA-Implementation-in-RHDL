use crate::dilithium_params::{Q, GAMMA2};

// Decompose r = r1 * alpha + r0
// Returns (r1, r0) such that r0 is in range.
// Parametrul `_alpha` este prefixat cu _ pentru că algoritmul standard
// folosește GAMMA2 direct, dar păstrăm semnătura generică.
pub fn decompose(mut r: i32, _alpha: i32) -> (i32, i32) {
    r = r % Q;
    if r < 0 { r += Q; }

    // Calculăm r1 direct, fără inițializări inutile
    let mut r1 = (r + 127) >> 7;
    
    if GAMMA2 == (Q - 1) / 32 {
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        r1 &= 15;
    } else if GAMMA2 == (Q - 1) / 88 { // Dilithium2 case
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        r1 ^= ((43 - r1) >> 31) & r1;
    }

    let mut r0 = r - r1 * 2 * GAMMA2;
    // Reduce mod Q centrat
    r0 = r0 % Q;
    if r0 < -(Q/2) { r0 += Q; }
    if r0 > Q/2 { r0 -= Q; }
    
    (r1, r0)
}

pub fn high_bits(r: i32, alpha: i32) -> i32 {
    let (r1, _) = decompose(r, 2 * alpha);
    r1
}

pub fn low_bits(r: i32, alpha: i32) -> i32 {
    let (_, r0) = decompose(r, 2 * alpha);
    r0
}

pub fn make_hint(z: i32, r: i32, alpha: i32) -> i32 {
    let r1 = high_bits(r, alpha);
    let v1 = high_bits(r + z, alpha);
    if r1 != v1 { 1 } else { 0 }
}

pub fn use_hint(r: i32, hint: u8, alpha: i32) -> i32 {
    let (r1, r0) = decompose(r, 2 * alpha);
    if hint == 0 {
        return r1;
    }
    
    if GAMMA2 == (Q - 1) / 32 {
        if r0 > 0 { (r1 + 1) & 15 } else { (r1 - 1) & 15 }
    } else {
        // Dilithium2 case
        if r0 > 0 { 
            if r1 == 43 { 0 } else { r1 + 1 }
        } else {
            if r1 == 0 { 43 } else { r1 - 1 }
        }
    }
}

pub fn power2round(mut r: i32, d: usize) -> (i32, i32) {
    r = r % Q;
    if r < 0 { r += Q; }

    let mask = (1 << d) - 1;
    let mut r0 = r & mask; // low d bits
    // centered remainder
    if r0 > (1 << (d - 1)) {
        r0 -= 1 << d; // Am scos parantezele inutile aici
    }
    let r1 = (r - r0) >> d;
    (r1, r0)
}

pub fn norm_bound(mut x: i32) -> i32 {
    x = x % Q;
    if x < 0 { x += Q; }
    if x > Q / 2 { x = Q - x; }
    x
}