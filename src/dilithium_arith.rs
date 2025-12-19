use crate::dilithium_params::Q;

#[inline(always)]
pub fn freeze(mut a: i32) -> i32 {
    // Bring into [0, Q)
    a %= Q;
    if a < 0 { a += Q; }
    a
}

#[inline(always)]
pub fn add_mod(a: i32, b: i32) -> i32 {
    let mut s = a + b;
    if s >= Q { s -= Q; }
    s
}

#[inline(always)]
pub fn sub_mod(a: i32, b: i32) -> i32 {
    let mut d = a - b;
    if d < 0 { d += Q; }
    d
}

#[inline(always)]
pub fn mul_mod(a: i32, b: i32) -> i32 {
    // i64 to avoid overflow: Q < 2^24, product < 2^48
    ((a as i64 * b as i64) % (Q as i64)) as i32
}

pub fn pow_mod(mut base: i32, mut exp: i64) -> i32 {
    let mut acc: i32 = 1;
    base = freeze(base);
    while exp > 0 {
        if (exp & 1) == 1 {
            acc = mul_mod(acc, base);
        }
        base = mul_mod(base, base);
        exp >>= 1;
    }
    acc
}

pub fn inv_mod(a: i32) -> i32 {
    // Fermat: a^(Q-2) mod Q, since Q is prime in Dilithium
    pow_mod(a, (Q as i64) - 2)
}
