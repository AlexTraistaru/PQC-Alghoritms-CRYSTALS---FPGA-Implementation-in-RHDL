use rhdl::prelude::*;
use crate::kyber_params::{KYBER_Q, Q, QINV};

pub type Coeff = SignedBits<U16>;
pub type Wide = SignedBits<U32>;

/// R  = 2^16 mod q = 2285
/// R2 = R^2 mod q = 1353
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

/// Conditional subtract q (ref: csubq)
#[inline(always)]
pub fn csubq(a: Coeff) -> Coeff {
    let r: Coeff = a - s16(KYBER_Q);
    if r.is_negative() { a } else { r }
}

/// Barrett reduction (ref constant v = ((1<<26)+q/2)/q = 20159)
#[inline(always)]
pub fn barrett_reduce(a: Coeff) -> Coeff {
    let v: Wide = s32(20159);
    let a32: Wide = a.resize::<U32>();
    // t = ((v*a + 2^25) >> 26) * q
    let t: Wide = ((v * a32 + s32(1 << 25)) >> 26) * s32(KYBER_Q as i64);
    (a32 - t).resize::<U16>()
}

/// Wider-input Barrett reduction (useful when you already have a 32-bit intermediate)
#[inline(always)]
pub fn barrett_reduce_wide(a: Wide) -> Coeff {
    let v: Wide = s32(20159);
    let t: Wide = ((v * a + s32(1 << 25)) >> 26) * s32(KYBER_Q as i64);
    (a - t).resize::<U16>()
}

/// Freeze to canonical representative in [0,q)
#[inline(always)]
pub fn freeze(a: Coeff) -> Coeff {
    let r0 = barrett_reduce(a);
    // FIX: Q is i16 => convert to Coeff before adding
    let r1 = if r0.is_negative() { r0 + s16(Q as i32) } else { r0 };
    csubq(r1)
}

/// Montgomery reduction (Kyber reference):
/// int16_t montgomery_reduce(int32_t a) {
///   int16_t t = (int16_t)a * QINV;
///   t = (a - (int32_t)t*Q) >> 16;
///   return t;
/// }
#[inline(always)]
pub fn montgomery_reduce(a: Wide) -> Coeff {
    // Cast BEFORE multiply, exactly like (int16_t)a.
    let a16: Coeff = a.resize::<U16>();

    // t = (int16)a * QINV, then truncated to 16 bits
    let t: Coeff = (a16.resize::<U32>() * s16(QINV).resize::<U32>()).resize::<U16>();

    // (a - (int32)t*q) >> 16
    let r: Wide = (a - t.resize::<U32>() * s32(KYBER_Q as i64)) >> 16;
    r.resize::<U16>()
}

/// fqmul(a,b) = montgomery_reduce(a*b)
#[inline(always)]
pub fn fqmul(a: Coeff, b: Coeff) -> Coeff {
    montgomery_reduce(a.resize::<U32>() * b.resize::<U32>())
}

/// add modulo q with a single conditional subtract
#[inline(always)]
pub fn add_mod(a: Coeff, b: Coeff) -> Coeff {
    let t: SignedBits<U17> = a.resize::<U17>() + b.resize::<U17>();
    let t2: SignedBits<U17> = t - signed::<U17>(KYBER_Q as i128);
    if t2.is_non_negative() { t2.resize::<U16>() } else { t.resize::<U16>() }
}

/// sub modulo q with a single conditional add
#[inline(always)]
pub fn sub_mod(a: Coeff, b: Coeff) -> Coeff {
    let t: SignedBits<U17> = a.resize::<U17>() - b.resize::<U17>();
    let t2: SignedBits<U17> = t + signed::<U17>(KYBER_Q as i128);
    if t.is_negative() { t2.resize::<U16>() } else { t.resize::<U16>() }
}

/// to Montgomery domain: a*R (implemented as montgomery_reduce(a*R^2))
#[inline(always)]
pub fn tomont(a: Coeff) -> Coeff {
    montgomery_reduce(a.resize::<U32>() * s16(MONT_R2).resize::<U32>())
}

/// from Montgomery domain: montgomery_reduce(a)
#[inline(always)]
pub fn frommont(a: Coeff) -> Coeff {
    montgomery_reduce(a.resize::<U32>())
}
