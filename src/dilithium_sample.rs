use crate::shake::{shake128, shake256};
// Removed unused DilithiumParams
use crate::dilithium_params::{N, Q, K, L, ETA, GAMMA1};
use crate::dilithium_poly::{Poly, PolyVec, PolyMat};

// Uniform poly in [0,q) using rejection sampling from SHAKE128(seed||nonce)
pub fn poly_uniform(seed: &[u8], nonce: u16) -> Poly {
    let mut inbuf = Vec::with_capacity(seed.len() + 2);
    inbuf.extend_from_slice(seed);
    inbuf.push((nonce & 0xFF) as u8);
    inbuf.push((nonce >> 8) as u8);

    let mut buf = vec![0u8; 4096];
    shake128(&inbuf, &mut buf);

    let mut out = Poly::default();
    let mut ctr = 0usize;
    let mut pos = 0usize;

    while ctr < N && pos + 3 <= buf.len() {
        let t = (buf[pos] as u32) | ((buf[pos + 1] as u32) << 8) | ((buf[pos + 2] as u32) << 16);
        pos += 3;
        let a = (t & 0x7FFFFF) as i32; // 23 bits
        if a < Q {
            out.coeffs[ctr] = a;
            ctr += 1;
        }
    }
    if ctr < N {
        panic!("poly_uniform: stream exhausted");
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

pub fn poly_uniform_eta(seed: &[u8], nonce: u16) -> Poly {
    let mut inbuf = Vec::with_capacity(seed.len() + 2);
    inbuf.extend_from_slice(seed);
    inbuf.push((nonce & 0xFF) as u8);
    inbuf.push((nonce >> 8) as u8);

    let mut buf = vec![0u8; 256];
    shake256(&inbuf, &mut buf);

    let mut out = Poly::default();
    let mut ctr = 0usize;
    let mut pos = 0usize;

    while ctr < N && pos < buf.len() {
        let b = buf[pos];
        pos += 1;
        for shift in [0u8, 3u8] {
            if ctr >= N { break; }
            let t = (b >> shift) & 0x7;
            if t < 5 {
                out.coeffs[ctr] = ETA - (t as i32); 
                ctr += 1;
            }
        }
    }
    if ctr < N {
         panic!("poly_uniform_eta: stream exhausted");
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
    let mut inbuf = Vec::with_capacity(seed.len() + 2);
    inbuf.extend_from_slice(seed);
    inbuf.push((nonce & 0xFF) as u8);
    inbuf.push((nonce >> 8) as u8);

    let bits = 18usize; 
    let need = ((N * bits + 7) / 8) + 256; 
    
    let mut buf = vec![0u8; need];
    shake256(&inbuf, &mut buf);

    let mut out = Poly::default();
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    let mask = (1u32 << bits) - 1;

    let mut idx = 0usize;
    let mut buf_idx = 0usize;

    while idx < N && buf_idx < buf.len() {
        while acc_bits < bits as u32 && buf_idx < buf.len() {
            acc |= (buf[buf_idx] as u32) << acc_bits;
            acc_bits += 8;
            buf_idx += 1;
        }

        if acc_bits >= bits as u32 {
            let t = (acc & mask) as i32;
            acc >>= bits;
            acc_bits -= bits as u32;

            if t <= 2 * GAMMA1 - 2 {
                out.coeffs[idx] = (GAMMA1 - 1) - t;
                idx += 1;
            }
        } else {
            break;
        }
    }
    if idx < N {
        panic!("poly_uniform_gamma1: stream exhausted");
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
    use crate::dilithium_params::TAU;
    
    let mut buf = vec![0u8; 256];
    shake256(c_tilde, &mut buf);

    let mut out = Poly::default();
    let mut signs = 0u64;
    for i in 0..8 {
        signs |= (buf[i] as u64) << (8 * i);
    }

    let mut pos = 8usize;
    let mut used = [false; N];
    let mut count = 0usize;

    while count < TAU && pos < buf.len() {
        let b = buf[pos] as usize;
        pos += 1;
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
        // Result is in Montgomery domain but not normalized
        out.v[i] = acc;
    }
    out
}