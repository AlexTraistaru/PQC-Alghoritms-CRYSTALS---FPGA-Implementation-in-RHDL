// "Controller" software that runs the RHDL-style sampling FSMs from
// kyber_sampling_rhdl.rs, fed by an incremental SHAKE byte-stream (xof_stream.rs).

#![allow(dead_code)]
#![allow(non_snake_case)]

use rhdl::prelude::*;

use crate::kyber_params::{K, N, SYMBYTES};
use crate::kyber_poly::{poly_ntt, Poly, PolyVec};
use crate::kyber_sampling_rhdl::{
    cbd2_step, cbd3_step, parse_uniform_step, ByteStreamIn, Cbd2Phase, Cbd2State, Cbd3Phase,
    Cbd3State, ParsePhase, ParseUniformState,
};
use crate::xof_stream::ShakeStream;

pub type PolyMat = [[Poly; K]; K];

#[inline(always)]
fn b8(x: u8) -> Bits<U8> {
    // RHDL Bits implements From<u128>, not From<u8>
    bits(x as u128)
}

#[inline(always)]
fn zero_poly() -> Poly {
    [signed::<U16>(0); N]
}

#[inline(always)]
fn zero_mat() -> PolyMat {
    [[zero_poly(); K]; K]
}

/// Run ParseUniform FSM to completion, consuming bytes from a SHAKE128 stream.
fn run_parse_uniform(mut stream: ShakeStream) -> Poly {
    let mut mem = zero_poly();
    let mut st = ParseUniformState::reset();

    for _ in 0..250_000 {
        let want_byte = (!st.pend_valid) && (st.phase != ParsePhase::Done);

        let inp = if want_byte {
            ByteStreamIn { valid: true, data: b8(stream.next_u8()) }
        } else {
            ByteStreamIn { valid: false, data: b8(0) }
        };

        let (ns, out) = parse_uniform_step(st, inp);
        st = ns;

        if out.wr.we {
            let addr = out.wr.addr.raw() as usize;
            mem[addr] = out.wr.data;
        }
        if out.done {
            return mem;
        }
    }

    panic!("run_parse_uniform: FSM did not finish within bound");
}

fn run_cbd2(mut stream: ShakeStream) -> Poly {
    let mut mem = zero_poly();
    let mut st = Cbd2State::default();

    for _ in 0..250_000 {
        let want_byte = st.phase == Cbd2Phase::Collect;

        let inp = if want_byte {
            ByteStreamIn { valid: true, data: b8(stream.next_u8()) }
        } else {
            ByteStreamIn { valid: false, data: b8(0) }
        };

        let (ns, out) = cbd2_step(st, inp);
        st = ns;

        if out.wr.we {
            let addr = out.wr.addr.raw() as usize;
            mem[addr] = out.wr.data;
        }
        if out.done {
            return mem;
        }
    }

    panic!("run_cbd2: FSM did not finish within bound");
}

fn run_cbd3(mut stream: ShakeStream) -> Poly {
    let mut mem = zero_poly();
    let mut st = Cbd3State::default();

    for _ in 0..250_000 {
        let want_byte = st.phase == Cbd3Phase::Collect;

        let inp = if want_byte {
            ByteStreamIn { valid: true, data: b8(stream.next_u8()) }
        } else {
            ByteStreamIn { valid: false, data: b8(0) }
        };

        let (ns, out) = cbd3_step(st, inp);
        st = ns;

        if out.wr.we {
            let addr = out.wr.addr.raw() as usize;
            mem[addr] = out.wr.data;
        }
        if out.done {
            return mem;
        }
    }

    panic!("run_cbd3: FSM did not finish within bound");
}

pub fn gen_matrix(rho: &[u8; SYMBYTES], transposed: bool) -> PolyMat {
    let mut A = zero_mat();

    for i in 0..K {
        for j in 0..K {
            let mut inbuf = [0u8; SYMBYTES + 2];
            inbuf[..SYMBYTES].copy_from_slice(rho);

            let x = if transposed { i as u8 } else { j as u8 };
            let y = if transposed { j as u8 } else { i as u8 };
            inbuf[SYMBYTES] = x;
            inbuf[SYMBYTES + 1] = y;

            let stream = ShakeStream::shake128(&inbuf);
            let mut p = run_parse_uniform(stream);

            poly_ntt(&mut p);
            A[i][j] = p;
        }
    }

    A
}

pub fn poly_getnoise(seed: &[u8; SYMBYTES], nonce: u8, eta: usize) -> Poly {
    let mut inbuf = [0u8; SYMBYTES + 1];
    inbuf[..SYMBYTES].copy_from_slice(seed);
    inbuf[SYMBYTES] = nonce;

    let stream = ShakeStream::shake256(&inbuf);
    match eta {
        2 => run_cbd2(stream),
        3 => run_cbd3(stream),
        _ => panic!("poly_getnoise: eta must be 2 or 3 for Kyber512"),
    }
}

pub fn polyvec_getnoise(seed: &[u8; SYMBYTES], mut nonce: u8, eta: usize) -> (PolyVec, u8) {
    let mut v: PolyVec = [zero_poly(); K];
    for i in 0..K {
        v[i] = poly_getnoise(seed, nonce, eta);
        nonce = nonce.wrapping_add(1);
    }
    (v, nonce)
}
