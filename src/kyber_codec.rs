// Kyber Round3 packing/unpacking + compress/decompress for Kyber512 (k=2, du=10, dv=4).
// Uses the same Coeff type as kyber_poly.rs (SignedBits<U16>) so everything matches.

#![allow(dead_code)]

use rhdl::prelude::*;

use crate::kyber_arith::{freeze, Coeff};
use crate::kyber_params::{
    CIPHERTEXTBYTES, DU, DV, K, KYBER_N, KYBER_Q, POLYBYTES, POLYCOMPRESSEDBYTES_DU10,
    POLYCOMPRESSEDBYTES_DV4, POLYVECBYTES, PUBLICKEYBYTES,
};

pub type Poly = [Coeff; KYBER_N];
pub type PolyVec = [Poly; K];

#[inline(always)]
fn c16(x: i16) -> Coeff {
    signed::<U16>(x as i128)
}

#[inline(always)]
fn coeff_to_i16(x: Coeff) -> i16 {
    x.raw() as i16
}

#[inline(always)]
fn coeff_to_u16_canon(x: Coeff) -> u16 {
    // freeze => [0, q)
    coeff_to_i16(freeze(x)) as u16
}

#[inline(always)]
fn compress_coeff(a: Coeff, d: usize) -> u16 {
    // t = Round(2^d / q * a) mod 2^d, with a in [0,q)
    let aa = coeff_to_u16_canon(a) as u32;
    let q = KYBER_Q as u32;
    let t = (((aa << d) + (q / 2)) / q) & ((1u32 << d) - 1);
    t as u16
}

#[inline(always)]
fn decompress_coeff(t: u16, d: usize) -> Coeff {
    // Round(q/2^d * t)
    let q = KYBER_Q as u32;
    let x = (((t as u32) * q) + (1u32 << (d - 1))) >> d;
    c16(x as i16)
}

// -----------------------------------------------------------------------------
// 12-bit poly encode/decode (polys are assumed reduced, freeze applied internally)
// -----------------------------------------------------------------------------

pub fn poly_encode12(p: &Poly) -> [u8; POLYBYTES] {
    let mut out = [0u8; POLYBYTES];
    for i in 0..(KYBER_N / 2) {
        let t0 = coeff_to_u16_canon(p[2 * i]);
        let t1 = coeff_to_u16_canon(p[2 * i + 1]);
        out[3 * i + 0] = (t0 & 0xff) as u8;
        out[3 * i + 1] = ((t0 >> 8) as u8) | (((t1 & 0x0f) as u8) << 4);
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
    out
}

pub fn poly_decode12(b: &[u8; POLYBYTES]) -> Poly {
    let mut p = [c16(0); KYBER_N];
    for i in 0..(KYBER_N / 2) {
        let d0 = (b[3 * i + 0] as u16) | (((b[3 * i + 1] as u16) & 0x0f) << 8);
        let d1 = ((b[3 * i + 1] as u16) >> 4) | ((b[3 * i + 2] as u16) << 4);
        p[2 * i] = c16((d0 & 0x0fff) as i16);
        p[2 * i + 1] = c16((d1 & 0x0fff) as i16);
    }
    p
}

pub fn polyvec_encode12(v: &PolyVec) -> [u8; POLYVECBYTES] {
    let mut out = [0u8; POLYVECBYTES];
    for i in 0..K {
        let e = poly_encode12(&v[i]);
        out[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&e);
    }
    out
}

pub fn polyvec_decode12(b: &[u8; POLYVECBYTES]) -> PolyVec {
    let mut v = [[c16(0); KYBER_N]; K];
    for i in 0..K {
        let mut chunk = [0u8; POLYBYTES];
        chunk.copy_from_slice(&b[i * POLYBYTES..(i + 1) * POLYBYTES]);
        v[i] = poly_decode12(&chunk);
    }
    v
}

// -----------------------------------------------------------------------------
// msg <-> poly (Kyber message mapping)
// -----------------------------------------------------------------------------

pub fn poly_frommsg(m: &[u8; 32]) -> Poly {
    let mut p = [c16(0); KYBER_N];
    for i in 0..32 {
        for j in 0..8 {
            let bit = (m[i] >> j) & 1;
            p[8 * i + j] = if bit == 0 {
                c16(0)
            } else {
                c16(((KYBER_Q + 1) / 2) as i16)
            };
        }
    }
    p
}

pub fn poly_tomsg(p: &Poly) -> [u8; 32] {
    let mut m = [0u8; 32];
    for i in 0..32 {
        let mut b = 0u8;
        for j in 0..8 {
            let t = compress_coeff(p[8 * i + j], 1);
            b |= ((t & 1) as u8) << j;
        }
        m[i] = b;
    }
    m
}

// -----------------------------------------------------------------------------
// Kyber512 poly compress/uncompress (du=10, dv=4)
// -----------------------------------------------------------------------------

pub fn poly_compress_du10(p: &Poly) -> [u8; POLYCOMPRESSEDBYTES_DU10] {
    debug_assert_eq!(DU, 10);
    let mut out = [0u8; POLYCOMPRESSEDBYTES_DU10];
    for i in 0..(KYBER_N / 4) {
        let t0 = compress_coeff(p[4 * i + 0], 10);
        let t1 = compress_coeff(p[4 * i + 1], 10);
        let t2 = compress_coeff(p[4 * i + 2], 10);
        let t3 = compress_coeff(p[4 * i + 3], 10);

        out[5 * i + 0] = (t0 & 0xff) as u8;
        out[5 * i + 1] = ((t0 >> 8) as u8) | (((t1 & 0x3f) as u8) << 2);
        out[5 * i + 2] = ((t1 >> 6) as u8) | (((t2 & 0x0f) as u8) << 4);
        out[5 * i + 3] = ((t2 >> 4) as u8) | (((t3 & 0x03) as u8) << 6);
        out[5 * i + 4] = (t3 >> 2) as u8;
    }
    out
}

pub fn poly_decompress_du10(b: &[u8; POLYCOMPRESSEDBYTES_DU10]) -> Poly {
    debug_assert_eq!(DU, 10);
    let mut p = [c16(0); KYBER_N];
    for i in 0..(KYBER_N / 4) {
        let d0 = (b[5 * i + 0] as u16) | (((b[5 * i + 1] as u16) & 0x03) << 8);
        let d1 = ((b[5 * i + 1] as u16) >> 2) | (((b[5 * i + 2] as u16) & 0x0f) << 6);
        let d2 = ((b[5 * i + 2] as u16) >> 4) | (((b[5 * i + 3] as u16) & 0x3f) << 4);
        let d3 = ((b[5 * i + 3] as u16) >> 6) | ((b[5 * i + 4] as u16) << 2);

        p[4 * i + 0] = decompress_coeff(d0, 10);
        p[4 * i + 1] = decompress_coeff(d1, 10);
        p[4 * i + 2] = decompress_coeff(d2, 10);
        p[4 * i + 3] = decompress_coeff(d3, 10);
    }
    p
}

pub fn poly_compress_dv4(p: &Poly) -> [u8; POLYCOMPRESSEDBYTES_DV4] {
    debug_assert_eq!(DV, 4);
    let mut out = [0u8; POLYCOMPRESSEDBYTES_DV4];
    for i in 0..(KYBER_N / 2) {
        let t0 = compress_coeff(p[2 * i], 4);
        let t1 = compress_coeff(p[2 * i + 1], 4);
        out[i] = (t0 as u8) | ((t1 as u8) << 4);
    }
    out
}

pub fn poly_decompress_dv4(b: &[u8; POLYCOMPRESSEDBYTES_DV4]) -> Poly {
    debug_assert_eq!(DV, 4);
    let mut p = [c16(0); KYBER_N];
    for i in 0..(KYBER_N / 2) {
        let t0 = (b[i] & 0x0f) as u16;
        let t1 = (b[i] >> 4) as u16;
        p[2 * i] = decompress_coeff(t0, 4);
        p[2 * i + 1] = decompress_coeff(t1, 4);
    }
    p
}

// -----------------------------------------------------------------------------
// Public key / Ciphertext pack/unpack
// -----------------------------------------------------------------------------

pub fn pk_encode(t: &PolyVec, rho: &[u8; 32]) -> [u8; PUBLICKEYBYTES] {
    let mut pk = [0u8; PUBLICKEYBYTES];
    let tbytes = polyvec_encode12(t);
    pk[..POLYVECBYTES].copy_from_slice(&tbytes);
    pk[POLYVECBYTES..].copy_from_slice(rho);
    pk
}

pub fn pk_decode(pk: &[u8; PUBLICKEYBYTES]) -> (PolyVec, [u8; 32]) {
    let mut tbytes = [0u8; POLYVECBYTES];
    tbytes.copy_from_slice(&pk[..POLYVECBYTES]);
    let t = polyvec_decode12(&tbytes);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[POLYVECBYTES..]);
    (t, rho)
}

pub fn ct_encode(u: &PolyVec, v: &Poly) -> [u8; CIPHERTEXTBYTES] {
    let mut ct = [0u8; CIPHERTEXTBYTES];
    for i in 0..K {
        let cu = poly_compress_du10(&u[i]);
        ct[i * POLYCOMPRESSEDBYTES_DU10..(i + 1) * POLYCOMPRESSEDBYTES_DU10].copy_from_slice(&cu);
    }
    let cv = poly_compress_dv4(v);
    ct[K * POLYCOMPRESSEDBYTES_DU10..].copy_from_slice(&cv);
    ct
}

pub fn ct_decode(ct: &[u8; CIPHERTEXTBYTES]) -> (PolyVec, Poly) {
    let mut u = [[c16(0); KYBER_N]; K];
    for i in 0..K {
        let mut chunk = [0u8; POLYCOMPRESSEDBYTES_DU10];
        chunk.copy_from_slice(&ct[i * POLYCOMPRESSEDBYTES_DU10..(i + 1) * POLYCOMPRESSEDBYTES_DU10]);
        u[i] = poly_decompress_du10(&chunk);
    }
    let mut vchunk = [0u8; POLYCOMPRESSEDBYTES_DV4];
    vchunk.copy_from_slice(&ct[K * POLYCOMPRESSEDBYTES_DU10..]);
    let v = poly_decompress_dv4(&vchunk);
    (u, v)
}
