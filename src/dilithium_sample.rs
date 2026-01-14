// Fix major correctness issue: do NOT use fixed buffers that can "run out".
// SHAKE is an XOF => infinite stream. We use xof_stream::ShakeStream.

#![allow(dead_code)]

use crate::dilithium_params::{N, Q, K, L, ETA, GAMMA1, TAU};
use crate::dilithium_poly::{Poly, PolyVec, PolyMat};
use crate::xof_stream::ShakeStream;

// Uniform poly in [0,q) using rejection sampling from SHAKE128(seed||nonce)
pub fn poly_uniform(seed: &[u8], nonce: u16) -> Poly {
    let mut inbuf = [0u8; 34];
    let n0 = (nonce & 0xFF) as u8;
    let n1 = (nonce >> 8) as u8;

    // seed is expected 32 bytes in Dilithium usage, but keep it generic:
    // If seed != 32, we still hash the provided bytes by building a small Vec? NO.
    // For your project, seed sizes are fixed (rho:32). We'll assume seed.len()==32.
    assert_eq!(seed.len(), 32, "poly_uniform expects 32-byte seed");
    inbuf[..32].copy_from_slice(seed);
    inbuf[32] = n0;
    inbuf[33] = n1;

    let mut stream = ShakeStream::shake128(&inbuf);

    let mut out = Poly::default();
    let mut ctr = 0usize;

    while ctr < N {
        let b0 = stream.next_u8() as u32;
        let b1 = stream.next_u8() as u32;
        let b2 = stream.next_u8() as u32;

        let t = b0 | (b1 << 8) | (b2 << 16);
        let a = (t & 0x7FFFFF) as i32; // 23-bit
        if a < Q {
            out.coeffs[ctr] = a;
            ctr += 1;
        }
    }

    out
}

pub fn expand_a(rho: &[u8; 32]) -> PolyMat<K, L> {
    let mut mat = PolyMat::<K, L>::default();
    for i in 0..K {
        for j in 0..L {
            let nonce = ((i as u16) << 8) | (j as u16);
            mat.m[i][j] = poly_uniform(rho, nonce);
            mat.m[i][j].ntt();
        }
    }
    mat
}

// Sample with small coefficients (your existing mapping logic), now using SHAKE256 stream.
pub fn poly_uniform_eta(seed: &[u8], nonce: u16) -> Poly {
    assert_eq!(seed.len(), 64, "poly_uniform_eta expects 64-byte seed (rho_prime)");
    let mut inbuf = [0u8; 66];
    inbuf[..64].copy_from_slice(seed);
    inbuf[64] = (nonce & 0xFF) as u8;
    inbuf[65] = (nonce >> 8) as u8;

    let mut stream = ShakeStream::shake256(&inbuf);

    let mut out = Poly::default();
    let mut ctr = 0usize;

    while ctr < N {
        let b = stream.next_u8();
        for shift in [0u8, 3u8] {
            if ctr >= N {
                break;
            }
            let t = (b >> shift) & 0x7;
            if t < 5 {
                // Same mapping as your previous code
                out.coeffs[ctr] = ETA - (t as i32);
                ctr += 1;
            }
        }
    }

    out
}

pub fn expand_s(rho_prime: &[u8]) -> (PolyVec<L>, PolyVec<K>) {
    let mut s1 = PolyVec::<L>::default();
    let mut s2 = PolyVec::<K>::default();

    let mut nonce = 0u16;
    for i in 0..L {
        s1.v[i] = poly_uniform_eta(rho_prime, nonce);
        nonce = nonce.wrapping_add(1);
    }
    for i in 0..K {
        s2.v[i] = poly_uniform_eta(rho_prime, nonce);
        nonce = nonce.wrapping_add(1);
    }
    (s1, s2)
}

pub fn poly_uniform_gamma1(seed: &[u8], nonce: u16) -> Poly {
    assert_eq!(seed.len(), 64, "poly_uniform_gamma1 expects 64-byte seed (rho_prime)");
    let mut inbuf = [0u8; 66];
    inbuf[..64].copy_from_slice(seed);
    inbuf[64] = (nonce & 0xFF) as u8;
    inbuf[65] = (nonce >> 8) as u8;

    let mut stream = ShakeStream::shake256(&inbuf);

    let bits = 18usize;
    let mask = (1u32 << bits) - 1;

    let mut out = Poly::default();
    let mut idx = 0usize;

    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;

    while idx < N {
        while acc_bits < bits as u32 {
            let b = stream.next_u8() as u32;
            acc |= b << acc_bits;
            acc_bits += 8;
        }

        let t = (acc & mask) as i32;
        acc >>= bits;
        acc_bits -= bits as u32;

        // Your old condition: t <= 2*GAMMA1 - 2
        // With bits=18 and GAMMA1=2^17 => reject only one value (262143).
        if t <= 2 * GAMMA1 - 2 {
            out.coeffs[idx] = (GAMMA1 - 1) - t;
            idx += 1;
        }
    }

    out
}

pub fn expand_mask(rho_prime: &[u8], kappa: u16) -> PolyVec<L> {
    let mut y = PolyVec::<L>::default();
    let mut nonce = kappa;
    for i in 0..L {
        y.v[i] = poly_uniform_gamma1(rho_prime, nonce);
        nonce = nonce.wrapping_add(1);
    }
    y
}

pub fn challenge(c_tilde: &[u8; 32]) -> Poly {
    let mut stream = ShakeStream::shake256(c_tilde);

    let mut out = Poly::default();

    // signs from first 8 bytes
    let mut signs: u64 = 0;
    for i in 0..8 {
        signs |= (stream.next_u8() as u64) << (8 * i);
    }

    let mut used = [false; N];
    let mut count = 0usize;

    while count < TAU {
        let b = stream.next_u8() as usize;
        if b < N && !used[b] {
            used[b] = true;
            let s = if (signs & 1) == 1 { -1 } else { 1 };
            signs >>= 1;
            out.coeffs[b] = s;
            count += 1;
        }
    }

    out
}

pub fn mat_vec_mul_ntt(a_hat: &PolyMat<K, L>, y: &PolyVec<L>) -> PolyVec<K> {
    let mut y_hat = *y;
    y_hat.ntt();

    let mut out = PolyVec::<K>::default();
    for i in 0..K {
        let mut acc = Poly::default();
        for j in 0..L {
            let t = Poly::pointwise_mul(&a_hat.m[i][j], &y_hat.v[j]);
            acc.add_assign(&t);
        }
        acc.intt();
        out.v[i] = acc;
    }
    out
}
