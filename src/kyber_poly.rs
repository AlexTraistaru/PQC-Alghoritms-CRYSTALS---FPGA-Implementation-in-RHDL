// Kyber polynomial helpers (poly/polyvec), packing/compression, and CBD noise sampler.
//
// NOTE: `kyber_arith.rs` and `kyber_ntt.rs` are treated as references and MUST NOT be changed.
// This file adapts the polynomial layer to those modules.

#![allow(dead_code)]
#![allow(non_snake_case)]

use rhdl::prelude::*;

use crate::kyber_arith::{barrett_reduce, csubq, fqmul, freeze, montgomery_reduce, Coeff};
use crate::kyber_ntt::{ntt_step, MemReq, NttIn, NttState};
use crate::kyber_params::*;
use crate::shake::shake256;

/// Polynomial type used across Kyber modules.
pub type Poly = [Coeff; N];

/// Vector of K polynomials.
pub type PolyVec = [Poly; K];

#[inline(always)]
fn c16(x: i16) -> Coeff {
    signed::<U16>(x as i128)
}

#[inline(always)]
fn coef_to_i16(x: Coeff) -> i16 {
    x.raw() as i16
}

#[inline(always)]
fn coef_to_u16(x: Coeff) -> u16 {
    coef_to_i16(x) as u16
}

// -----------------------------------------------------------------------------
// NTT wrapper (software simulation of the BRAM-style FSM in `kyber_ntt.rs`)
// -----------------------------------------------------------------------------

#[inline(always)]
fn mem_read(mem: &Poly, addr: Bits<U8>) -> Coeff {
    mem[addr.raw() as usize]
}

#[inline(always)]
fn mem_write(mem: &mut Poly, req: MemReq) {
    if req.we {
        mem[req.addr.raw() as usize] = req.wdata;
    }
}

/// Runs the reference NTT FSM (from `kyber_ntt.rs`) to completion on a local array.
///
/// The FSM assumes 1-cycle synchronous read latency (Read -> Write), which we emulate.
fn run_ntt(mem: &mut Poly, inverse: bool) {
    let mut st = NttState::default();

    let mut start = true;

    // Pending read addresses (issued in the previous cycle).
    let mut pending_read_a: Bits<U8> = bits(0u128);
    let mut pending_read_b: Bits<U8> = bits(0u128);
    let mut pending_valid = false;

    // Data to present as synchronous BRAM outputs.
    let mut rdata_a = c16(0);
    let mut rdata_b = c16(0);

    // Safety bound: 256-pt NTT with 2-cycle butterflies + final pass fits well under this.
    for _cycle in 0..20_000 {
        if pending_valid {
            rdata_a = mem_read(mem, pending_read_a);
            rdata_b = mem_read(mem, pending_read_b);
        } else {
            rdata_a = c16(0);
            rdata_b = c16(0);
        }

        let inp = NttIn {
            start,
            inverse,
            rdata_a,
            rdata_b,
        };

        let (ns, out) = ntt_step(st, inp);
        st = ns;

        // Apply writes (same-cycle).
        mem_write(mem, out.porta);
        mem_write(mem, out.portb);

        // Capture next cycle's reads (only when ports are in read mode).
        pending_valid = !out.porta.we; // Read phases set porta.we=false.
        if pending_valid {
            pending_read_a = out.porta.addr;
            pending_read_b = out.portb.addr;
        }

        start = false;

        if out.done {
            return;
        }
    }

    panic!("NTT FSM did not finish within the cycle bound");
}

// -----------------------------------------------------------------------------
// Basic polynomial ops
// -----------------------------------------------------------------------------

pub fn poly_reduce(a: &mut Poly) {
    for i in 0..N {
        a[i] = barrett_reduce(a[i]);
    }
}

pub fn poly_csubq(a: &mut Poly) {
    for i in 0..N {
        a[i] = csubq(a[i]);
    }
}

/// Forward NTT.
pub fn poly_ntt(a: &mut Poly) {
    const R2: i16 = 1353;
    let r2 = c16(R2);
    for i in 0..N {
        a[i] = fqmul(a[i], r2);
    }

    run_ntt(a, false);
    poly_reduce(a);
}

/// Inverse NTT.
pub fn poly_invntt(a: &mut Poly) {
    run_ntt(a, true);

    for i in 0..N {
        a[i] = montgomery_reduce(a[i].resize::<U32>());
        a[i] = montgomery_reduce(a[i].resize::<U32>());
    }
}

#[inline(always)]
fn basemul(
    r0: &mut Coeff,
    r1: &mut Coeff,
    a0: Coeff,
    a1: Coeff,
    b0: Coeff,
    b1: Coeff,
    zeta: Coeff,
) {
    let t0 = fqmul(a1, b1);
    let t0z = fqmul(t0, zeta);
    let t1 = fqmul(a0, b0);
    *r0 = t1 + t0z;

    let t2 = fqmul(a0, b1);
    let t3 = fqmul(a1, b0);
    *r1 = t2 + t3;
}

pub fn poly_basemul_montgomery(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..(N / 4) {
        let zeta = c16(ZETAS[64 + i]);

        let mut r0 = c16(0);
        let mut r1 = c16(0);
        basemul(&mut r0, &mut r1, a[4 * i], a[4 * i + 1], b[4 * i], b[4 * i + 1], zeta);
        r[4 * i] = r0;
        r[4 * i + 1] = r1;

        let mut r2 = c16(0);
        let mut r3 = c16(0);
        basemul(
            &mut r2,
            &mut r3,
            a[4 * i + 2],
            a[4 * i + 3],
            b[4 * i + 2],
            b[4 * i + 3],
            -zeta,
        );
        r[4 * i + 2] = r2;
        r[4 * i + 3] = r3;
    }
}

pub fn poly_add(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = a[i] + b[i];
    }
}

pub fn poly_sub(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = a[i] - b[i];
    }
}

pub fn polyvec_ntt(v: &mut PolyVec) {
    for i in 0..K {
        poly_ntt(&mut v[i]);
    }
}

pub fn polyvec_invntt(v: &mut PolyVec) {
    for i in 0..K {
        poly_invntt(&mut v[i]);
    }
}

/// r = sum_i a[i] ⊙ b[i] (NTT domain), then reduce.
pub fn polyvec_pointwise_acc(r: &mut Poly, a: &PolyVec, b: &PolyVec) {
    let mut tmp = [c16(0); N];

    poly_basemul_montgomery(r, &a[0], &b[0]);
    for i in 1..K {
        poly_basemul_montgomery(&mut tmp, &a[i], &b[i]);
        for j in 0..N {
            r[j] = r[j] + tmp[j];
        }
    }

    poly_reduce(r);
}

// -----------------------------------------------------------------------------
// Packing/unpacking (12-bit)
// -----------------------------------------------------------------------------

pub fn poly_tobytes(out: &mut [u8; POLYBYTES], a: &Poly) {
    let mut t = [0u16; N];
    for i in 0..N {
        t[i] = coef_to_u16(freeze(a[i]));
    }
    for i in 0..128 {
        let t0 = t[2 * i];
        let t1 = t[2 * i + 1];
        out[3 * i] = (t0 & 0xFF) as u8;
        out[3 * i + 1] = ((t0 >> 8) as u8) | ((t1 << 4) as u8);
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
}

pub fn poly_frombytes(a: &mut Poly, inp: &[u8; POLYBYTES]) {
    for i in 0..128 {
        let b0 = inp[3 * i] as u16;
        let b1 = inp[3 * i + 1] as u16;
        let b2 = inp[3 * i + 2] as u16;

        let v0 = (b0 | ((b1 & 0x0F) << 8)) as i16;
        let v1 = (((b1 >> 4) | (b2 << 4)) & 0x0FFF) as i16;

        a[2 * i] = c16(v0);
        a[2 * i + 1] = c16(v1);
    }
}

// -----------------------------------------------------------------------------
// Compression/decompression
// -----------------------------------------------------------------------------

pub fn poly_compress_du10(out: &mut [u8; POLYCOMPRESSEDBYTES_DU10], a: &Poly) {
    let mut k = 0usize;
    for i in 0..(N / 4) {
        let mut t = [0u16; 4];
        for j in 0..4 {
            let v = coef_to_u16(freeze(a[4 * i + j])) as u32;
            let num = (v << 10).wrapping_add((Q as u32) / 2);
            t[j] = (num / (Q as u32)) as u16 & 0x03FF;
        }
        out[k + 0] = (t[0] & 0xFF) as u8;
        out[k + 1] = ((t[0] >> 8) as u8) | ((t[1] << 2) as u8);
        out[k + 2] = ((t[1] >> 6) as u8) | ((t[2] << 4) as u8);
        out[k + 3] = ((t[2] >> 4) as u8) | ((t[3] << 6) as u8);
        out[k + 4] = (t[3] >> 2) as u8;
        k += 5;
    }
}

pub fn poly_decompress_du10(a: &mut Poly, inp: &[u8; POLYCOMPRESSEDBYTES_DU10]) {
    let mut k = 0usize;
    for i in 0..(N / 4) {
        let t0 = (inp[k + 0] as u16) | (((inp[k + 1] as u16) & 0x03) << 8);
        let t1 = ((inp[k + 1] as u16) >> 2) | (((inp[k + 2] as u16) & 0x0F) << 6);
        let t2 = ((inp[k + 2] as u16) >> 4) | (((inp[k + 3] as u16) & 0x3F) << 4);
        let t3 = ((inp[k + 3] as u16) >> 6) | ((inp[k + 4] as u16) << 2);
        let ts = [t0, t1, t2, t3];
        for j in 0..4 {
            let v = (((ts[j] as u32) * (Q as u32) + 512) >> 10) as i16;
            a[4 * i + j] = c16(v);
        }
        k += 5;
    }
}

pub fn poly_compress_dv4(out: &mut [u8; POLYCOMPRESSEDBYTES_DV4], a: &Poly) {
    for i in 0..(N / 2) {
        let a0 = coef_to_u16(freeze(a[2 * i])) as u32;
        let a1 = coef_to_u16(freeze(a[2 * i + 1])) as u32;

        let num0 = (a0 << 4).wrapping_add((Q as u32) / 2);
        let num1 = (a1 << 4).wrapping_add((Q as u32) / 2);

        let t0 = (num0 / (Q as u32)) as u8 & 0x0F;
        let t1 = (num1 / (Q as u32)) as u8 & 0x0F;
        out[i] = t0 | (t1 << 4);
    }
}

pub fn poly_decompress_dv4(a: &mut Poly, inp: &[u8; POLYCOMPRESSEDBYTES_DV4]) {
    for i in 0..(N / 2) {
        let t0 = (inp[i] & 0x0F) as u32;
        let t1 = (inp[i] >> 4) as u32;
        a[2 * i] = c16(((t0 * (Q as u32) + 8) >> 4) as i16);
        a[2 * i + 1] = c16(((t1 * (Q as u32) + 8) >> 4) as i16);
    }
}

// -----------------------------------------------------------------------------
// msg <-> poly
// -----------------------------------------------------------------------------

pub fn poly_frommsg(r: &mut Poly, msg: &[u8; SYMBYTES]) {
    let v: i16 = ((Q as i32 + 1) / 2) as i16; // 1665 for q=3329
    for i in 0..N {
        let bit = (msg[i >> 3] >> (i & 7)) & 1;
        r[i] = if bit == 1 { c16(v) } else { c16(0) };
    }
}

pub fn poly_tomsg(msg: &mut [u8; 32], a: &Poly) {
    for i in 0..32 {
        let mut byte = 0u8;
        for j in 0..8 {
            let mut t = coef_to_i16(a[8 * i + j]) as i32;
            if t < 0 {
                t += Q as i32;
            }

            let val = ((t as u32) << 1).wrapping_add((Q as u32) / 2);
            let bit = (val / (Q as u32)) & 1;
            byte |= (bit as u8) << j;
        }
        msg[i] = byte;
    }
}

// -----------------------------------------------------------------------------
// Noise: PRF + CBD (eta1=3, eta2=2)
// -----------------------------------------------------------------------------

fn load24_le(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16)
}

fn load32_le(x: &[u8]) -> u32 {
    (x[0] as u32)
        | ((x[1] as u32) << 8)
        | ((x[2] as u32) << 16)
        | ((x[3] as u32) << 24)
}

fn prf(out: &mut [u8], key: &[u8; SYMBYTES], nonce: u8) {
    let mut inbuf = [0u8; 33];
    inbuf[..32].copy_from_slice(key);
    inbuf[32] = nonce;
    shake256(&inbuf, out);
}

fn cbd_eta1(r: &mut Poly, buf: &[u8]) {
    for i in 0..(N / 4) {
        let t = load24_le(&buf[3 * i..3 * i + 3]);

        let mut d = t & 0x0024_9249;
        d = d.wrapping_add((t >> 1) & 0x0024_9249);
        d = d.wrapping_add((t >> 2) & 0x0024_9249);

        for j in 0..4 {
            let a0 = ((d >> (6 * j)) & 0x7) as i16;
            let b0 = ((d >> (6 * j + 3)) & 0x7) as i16;
            r[4 * i + j] = c16(a0.wrapping_sub(b0));
        }
    }
}

fn cbd_eta2(r: &mut Poly, buf: &[u8]) {
    for i in 0..(N / 8) {
        let t = load32_le(&buf[4 * i..4 * i + 4]);

        let mut d = t & 0x5555_5555;
        d = d.wrapping_add((t >> 1) & 0x5555_5555);

        for j in 0..8 {
            let a0 = ((d >> (4 * j)) & 0x3) as i16;
            let b0 = ((d >> (4 * j + 2)) & 0x3) as i16;
            r[8 * i + j] = c16(a0.wrapping_sub(b0));
        }
    }
}

pub fn cbd_eta(out: &mut Poly, eta: usize, key: &[u8; SYMBYTES], nonce: u8) {
    let buflen = eta * N / 4;
    let mut buf = vec![0u8; buflen];
    prf(&mut buf, key, nonce);

    match eta {
        3 => cbd_eta1(out, &buf),
        2 => cbd_eta2(out, &buf),
        _ => panic!("Kyber: eta must be 2 or 3"),
    }
}
