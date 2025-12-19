//use std::arch::x86_64;

// src/kyber_arith.rs
// Aritmetică Kyber: Montgomery + Barrett + helper ops (compatibil cu ref). :contentReference[oaicite:3]{index=3}
use rhdl::prelude::*;
use crate::kyber_params::{KYBER_Q, QINV};

pub type Coeff = SignedBits<U16>;
pub type Wide  = SignedBits<U32>;

/// Montgomery helpers
/// R  = 2^16 mod q = 2285
/// R2 = R^2 mod q = 1353  (used in poly_tomont in Kyber ref)
pub const MONT_R: i32 = 2285;
pub const MONT_R2: i32 = 1353;

#[inline(always)]
pub fn s16(x: i32) -> Coeff {
    signed::<U16>(x as i128)
}
#[inline(always)]
pub fn s32(x: i64) -> Wide {
    signed::<U32>(x as i128)
}


/// Conditional subtract q (ref csubq):
/// r = a - q; if r < 0 => a else r
#[inline(always)]
pub fn csubq(a: Coeff) -> Coeff {
    let r: Coeff = a - s16(KYBER_Q);
    if r.is_negative() { a } else { r }
}

/// Freeze (canonical representative):
/// (barrett + conditional adds/subs) => [0,q)
#[inline(always)]
pub fn freeze(a: Coeff) -> Coeff {
    let r0 = barrett_reduce(a);
    // make positive
    let r1 = if r0.is_negative() { r0 + s16(KYBER_Q) } else { r0 };
    csubq(r1)
}

/// Montgomery reduction (Kyber ref):
/// int16_t montgomery_reduce(int32_t a) {
///   int16_t t = (int16_t)a * QINV;
///   t = (a - (int32_t)t*Q) >> 16;
///   return t;
/// }
#[inline(always)]
pub fn montgomery_reduce(a: Wide) -> Coeff {
    // t = (a * QINV) truncated to 16 bits
    let t: Coeff = (a * s32(QINV as i64)).resize::<U16>();
    // r = (a - t*Q) >> 16
    let r: Wide = (a - t.resize::<U32>() * s32(KYBER_Q as i64)) >> 16;
    r.resize::<U16>()
}

/// fqmul(a,b) = montgomery_reduce(a*b) (Kyber ref)
#[inline(always)]
pub fn fqmul(a: Coeff, b: Coeff) -> Coeff {
    montgomery_reduce(a.resize::<U32>() * b.resize::<U32>())
}

/// Kyber Barrett reduce (ref):
/// v = ((1<<26) + q/2)/q = 20159
#[inline(always)]
pub fn barrett_reduce(a: Coeff) -> Coeff {
    let v: Wide = s32(20159);
    let a32: Wide = a.resize::<U32>();

    // t = ((v*a + 2^25) >> 26) * q
    let t: Wide = ((v * a32 + s32(1 << 25)) >> 26) * s32(KYBER_Q as i64);

    (a32 - t).resize::<U16>()
}

#[inline(always)]
pub fn sub(a: SignedBits<U16>, b: SignedBits<U16>) -> SignedBits<U16> {
    let t: SignedBits<U17> = a.resize::<U17>() - b.resize::<U17>();
    let t2: SignedBits<U17> = t + signed::<U17>(KYBER_Q as i128);
    
    // if t < 0 => t+q else t
    if t.is_negative() {
        t2.resize::<U16>()
    } else {
        t.resize::<U16>()
    }
}


#[inline(always)]
pub fn add(a: SignedBits<U16>, b: SignedBits<U16>) -> SignedBits<U16> {
    let t: SignedBits<U17> = a.resize::<U17>() + b.resize::<U17>();
    let t2: SignedBits<U17> = t - signed::<U17>(KYBER_Q as i128);

    // if t2 >= 0 => t2 else t
    if t2.is_non_negative() {
        t2.resize::<U16>()
    } else {
        t.resize::<U16>()
    }
}

/// to Montgomery: a*R (implemented as montgomery_reduce(a*R^2))
#[inline(always)]
pub fn tomont(a: Coeff) -> Coeff {
    montgomery_reduce(a.resize::<U32>() * s16(MONT_R2).resize::<U32>())
}

/// from Montgomery: montgomery_reduce(a)
#[inline(always)]
pub fn frommont(a: Coeff) -> Coeff {
    montgomery_reduce(a.resize::<U32>())
}