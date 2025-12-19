// src/kyber_indcpa.rs
// Kyber IND-CPA (keypair/encrypt/decrypt) built on top of kyber_poly + kyber_arith + kyber_ntt.
//
// NOTE: `kyber_arith.rs` and `kyber_ntt.rs` are treated as references and MUST NOT be changed.

#![allow(dead_code)]
#![allow(non_snake_case)]

use rhdl::prelude::*;

use crate::kyber_arith::Coeff;
use crate::kyber_params::*;
use crate::kyber_poly::*;
use crate::shake::{sha3_512, shake128};

#[inline(always)]
fn c16(x: i16) -> Coeff {
    signed::<U16>(x as i128)
}

fn rej_uniform(out: &mut Poly, seed: &[u8; SYMBYTES], i: u8, j: u8) {
    // XOF = SHAKE128(seed||i||j)
    let mut ext = [0u8; 34];
    ext[..32].copy_from_slice(seed);
    ext[32] = i;
    ext[33] = j;

    // IMPORTANT: 672 bytes are typically enough, but not provably always.
    // We re-squeeze by re-calling shake128 with a larger output (prefix property).
    let mut buf_len = 672usize;
    let mut buf = vec![0u8; buf_len];
    shake128(&ext, &mut buf);

    let mut ctr = 0usize;
    let mut pos = 0usize;

    while ctr < N {
        if pos + 3 > buf.len() {
            buf_len += 672;
            buf = vec![0u8; buf_len];
            shake128(&ext, &mut buf);
            continue;
        }

        let d0 = (buf[pos] as u16) | (((buf[pos + 1] as u16) & 0x0F) << 8);
        let d1 = ((buf[pos + 1] as u16) >> 4) | ((buf[pos + 2] as u16) << 4);
        pos += 3;

        if d0 < (Q as u16) {
            out[ctr] = c16(d0 as i16);
            ctr += 1;
        }
        if ctr < N && d1 < (Q as u16) {
            out[ctr] = c16(d1 as i16);
            ctr += 1;
        }
    }
}

fn gen_matrix(a: &mut [[Poly; K]; K], rho: &[u8; SYMBYTES], transposed: bool) {
    for i in 0..K {
        for j in 0..K {
            let (x, y) = if transposed {
                (j as u8, i as u8)
            } else {
                (i as u8, j as u8)
            };
            rej_uniform(&mut a[i][j], rho, x, y);
            poly_ntt(&mut a[i][j]);
        }
    }
}

pub fn indcpa_keypair(seed: &[u8; SYMBYTES]) -> ([u8; PUBLICKEYBYTES], [u8; INDCPA_SECRETKEYBYTES]) {
    let h = sha3_512(seed);
    let mut rho = [0u8; SYMBYTES];
    let mut sigma = [0u8; SYMBYTES];
    rho.copy_from_slice(&h[..32]);
    sigma.copy_from_slice(&h[32..]);

    let mut a = [[[c16(0); N]; K]; K];
    gen_matrix(&mut a, &rho, false);

    let mut s = [[c16(0); N]; K];
    let mut e = [[c16(0); N]; K];

    for i in 0..K {
        cbd_eta(&mut s[i], ETA1, &sigma, i as u8);
        cbd_eta(&mut e[i], ETA1, &sigma, (K + i) as u8);
        poly_ntt(&mut s[i]);
        poly_ntt(&mut e[i]);
    }

    let mut t = [[c16(0); N]; K];
    for i in 0..K {
        let mut acc = [c16(0); N];
        polyvec_pointwise_acc(&mut acc, &a[i], &s);
        poly_add(&mut t[i], &acc, &e[i]);
    }

    // pk = (t || rho)
    let mut pk = [0u8; PUBLICKEYBYTES];
    for i in 0..K {
        let mut tmp = [0u8; POLYBYTES];
        poly_tobytes(&mut tmp, &t[i]);
        pk[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&tmp);
    }
    pk[POLYVECBYTES..].copy_from_slice(&rho);

    // sk_indcpa = s
    let mut sk = [0u8; INDCPA_SECRETKEYBYTES];
    for i in 0..K {
        let mut tmp = [0u8; POLYBYTES];
        poly_tobytes(&mut tmp, &s[i]);
        sk[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&tmp);
    }

    (pk, sk)
}

pub fn indcpa_enc(
    ct: &mut [u8; CIPHERTEXTBYTES],
    m: &[u8; SYMBYTES],
    pk: &[u8; PUBLICKEYBYTES],
    coins: &[u8; SYMBYTES],
) {
    // unpack pk
    let mut t = [[c16(0); N]; K];
    for i in 0..K {
        let mut tmp = [0u8; POLYBYTES];
        tmp.copy_from_slice(&pk[i * POLYBYTES..(i + 1) * POLYBYTES]);
        poly_frombytes(&mut t[i], &tmp);
    }
    let mut rho = [0u8; SYMBYTES];
    rho.copy_from_slice(&pk[POLYVECBYTES..]);

    // gen A^T
    let mut at = [[[c16(0); N]; K]; K];
    gen_matrix(&mut at, &rho, true);

    // sample r,e1,e2
    let mut r = [[c16(0); N]; K];
    let mut e1 = [[c16(0); N]; K];
    let mut e2 = [c16(0); N];

    for i in 0..K {
        cbd_eta(&mut r[i], ETA1, coins, i as u8);
        cbd_eta(&mut e1[i], ETA2, coins, (K + i) as u8);
        poly_ntt(&mut r[i]);
    }
    cbd_eta(&mut e2, ETA2, coins, (2 * K) as u8);

    // u = invntt( A^T * r ) + e1
    let mut u = [[c16(0); N]; K];
    for i in 0..K {
        let mut acc = [c16(0); N];
        polyvec_pointwise_acc(&mut acc, &at[i], &r);
        poly_invntt(&mut acc);
        poly_add(&mut u[i], &acc, &e1[i]);
        poly_reduce(&mut u[i]);
    }

    // v = invntt(t^T*r) + e2 + m
    let mut acc = [c16(0); N];
    polyvec_pointwise_acc(&mut acc, &t, &r);
    poly_invntt(&mut acc);

    let mut mp = [c16(0); N];
    poly_frommsg(&mut mp, m);

    let mut v = [c16(0); N];
    poly_add(&mut v, &acc, &e2);
    let mut v2 = [c16(0); N];
    poly_add(&mut v2, &v, &mp);
    v = v2;
    poly_reduce(&mut v);

    // pack ct: c1 = compress(u,du=10) for each poly; c2 = compress(v,dv=4)
    let mut c1 = [0u8; POLYVECCOMPRESSEDBYTES];
    for i in 0..K {
        let mut tmp = [0u8; POLYCOMPRESSEDBYTES_DU10];
        poly_compress_du10(&mut tmp, &u[i]);
        c1[i * POLYCOMPRESSEDBYTES_DU10..(i + 1) * POLYCOMPRESSEDBYTES_DU10].copy_from_slice(&tmp);
    }
    let mut c2 = [0u8; POLYCOMPRESSEDBYTES_DV4];
    poly_compress_dv4(&mut c2, &v);

    ct[..POLYVECCOMPRESSEDBYTES].copy_from_slice(&c1);
    ct[POLYVECCOMPRESSEDBYTES..].copy_from_slice(&c2);
}

pub fn indcpa_dec(m: &mut [u8; SYMBYTES], ct: &[u8; CIPHERTEXTBYTES], sk: &[u8; INDCPA_SECRETKEYBYTES]) {
    // unpack sk (s)
    let mut s = [[c16(0); N]; K];
    for i in 0..K {
        let mut tmp = [0u8; POLYBYTES];
        tmp.copy_from_slice(&sk[i * POLYBYTES..(i + 1) * POLYBYTES]);
        poly_frombytes(&mut s[i], &tmp);
    }

    // unpack ct -> u,v
    let mut u = [[c16(0); N]; K];
    for i in 0..K {
        let mut tmp = [0u8; POLYCOMPRESSEDBYTES_DU10];
        tmp.copy_from_slice(&ct[i * POLYCOMPRESSEDBYTES_DU10..(i + 1) * POLYCOMPRESSEDBYTES_DU10]);
        poly_decompress_du10(&mut u[i], &tmp);
    }
    let mut vbytes = [0u8; POLYCOMPRESSEDBYTES_DV4];
    vbytes.copy_from_slice(&ct[POLYVECCOMPRESSEDBYTES..]);
    let mut v = [c16(0); N];
    poly_decompress_dv4(&mut v, &vbytes);

    // m = v - invntt(s^T * ntt(u))
    for i in 0..K {
        poly_ntt(&mut u[i]);
    }
    let mut acc = [c16(0); N];
    polyvec_pointwise_acc(&mut acc, &s, &u);
    poly_invntt(&mut acc);

    let mut mp = [c16(0); N];
    poly_sub(&mut mp, &v, &acc);
    poly_reduce(&mut mp);
    poly_tomsg(m, &mp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shake::sha3_256;

    #[test]
    fn test_indcpa_roundtrip() {
        let seed = [7u8; 32];
        let (pk, sk) = indcpa_keypair(&seed);

        let m = sha3_256(&[9u8; 32]);
        let coins = sha3_256(&[1u8; 32]);

        let mut ct = [0u8; CIPHERTEXTBYTES];
        indcpa_enc(&mut ct, &m, &pk, &coins);

        let mut m2 = [0u8; 32];
        indcpa_dec(&mut m2, &ct, &sk);

        assert_eq!(m, m2);
    }
}
