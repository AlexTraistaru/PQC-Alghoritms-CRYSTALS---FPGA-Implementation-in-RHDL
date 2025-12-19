// src/dilithium_ntt.rs
// Dilithium NTT/INTT hardware core in RHDL style (FSM + dual-port BRAM interface).
//
// No `for` / `while` used. The step function is fully FSM-based.
// Also provides software wrappers `ntt()` / `intt()` that simulate the FSM
// without using `for`/`while` keywords (uses iterators).

#![allow(dead_code)]
#![allow(non_snake_case)]

use rhdl::prelude::*;
use core::ops::ControlFlow;

use crate::dilithium_params::{N, Q, QINV, F, ZETAS};

pub type Coeff = SignedBits<U32>;
pub type Wide  = SignedBits<U64>;

#[inline(always)]
fn s32(x: i64) -> Coeff { signed::<U32>(x as i128) }
#[inline(always)]
fn s64(x: i128) -> Wide { signed::<U64>(x) }
#[inline(always)]
fn u8(x: u8) -> Bits<U8> { bits(x as u128) }
#[inline(always)]
fn u9(x: u16) -> Bits<U9> { bits(x as u128) }

#[derive(Copy, Clone, Default)]
pub struct MemReq {
    pub addr: Bits<U8>,
    pub we: bool,
    pub wdata: Coeff,
}

#[derive(Copy, Clone, Default)]
pub struct NttIn {
    pub start: bool,
    pub inverse: bool,
    pub rdata_a: Coeff,
    pub rdata_b: Coeff,
}

#[derive(Copy, Clone, Default)]
pub struct NttOut {
    pub porta: MemReq,
    pub portb: MemReq,
    pub busy: bool,
    pub done: bool,
}

#[derive(Copy, Clone, PartialEq)]
pub enum Phase {
    Idle,
    Read,
    Write,
    FinalRead,
    FinalWrite,
    Done,
}
impl Default for Phase {
    fn default() -> Self { Phase::Idle }
}

#[derive(Copy, Clone, Default)]
pub struct NttState {
    pub phase: Phase,
    pub inverse: bool,

    pub len: Bits<U9>,     // forward: 128..1, inverse: 1..128
    pub start: Bits<U9>,   // block start
    pub j: Bits<U9>,       // index within stage
    pub k: Bits<U9>,       // zeta index (fwd inc, inv dec)

    pub idx: Bits<U9>,     // final scaling index (inverse only)
}

#[inline(always)]
fn zeta_fwd(k: u16) -> Coeff {
    s32(ZETAS[k as usize] as i64)
}
#[inline(always)]
fn zeta_inv(k: u16) -> Coeff {
    s32((-(ZETAS[k as usize])) as i64)
}

#[inline(always)]
pub fn montgomery_reduce(a: Wide) -> Coeff {
    // t = (int32)a * QINV (mod 2^32)
    // r = (a - t*Q) >> 32
    let t: Coeff = (a.resize::<U32>() * s32(QINV as i64)).resize::<U32>();
    let r: Wide = (a - t.resize::<U64>() * s64(Q as i128)) >> 32;
    r.resize::<U32>()
}

#[inline(always)]
pub fn fqmul(a: Coeff, b: Coeff) -> Coeff {
    let prod: Wide = (a.resize::<U64>() * b.resize::<U64>()).resize::<U64>();
    montgomery_reduce(prod)
}

/// One-cycle Dilithium NTT/INTT step.
/// - forward: CT butterfly (produces bitreversed output)
/// - inverse: GS butterfly + final scaling by F (invntt_tomont)
pub fn ntt_step(st: NttState, inp: NttIn) -> (NttState, NttOut) {
    let mut ns = st;
    let mut out = NttOut::default();

    out.busy = st.phase != Phase::Idle && st.phase != Phase::Done;
    out.done = st.phase == Phase::Done;

    match st.phase {
        Phase::Idle => {
            out.done = false;
            if inp.start {
                ns.inverse = inp.inverse;
                ns.start = u9(0);
                ns.j = u9(0);
                ns.idx = u9(0);

                if inp.inverse {
                    ns.len = u9(1);
                    ns.k = u9(255);
                } else {
                    ns.len = u9(128);
                    ns.k = u9(1);
                }

                ns.phase = Phase::Read;
            }
        }

        Phase::Read => {
            out.porta.addr = st.j.resize::<U8>();
            out.porta.we = false;

            out.portb.addr = (st.j + st.len).resize::<U8>();
            out.portb.we = false;

            ns.phase = Phase::Write;
        }

        Phase::Write => {
            let a = inp.rdata_a;
            let b = inp.rdata_b;

            let z = if st.inverse {
                zeta_inv(st.k.raw() as u16)
            } else {
                zeta_fwd(st.k.raw() as u16)
            };

            let (wa, wb) = if st.inverse {
                // inv: a' = a + b ; b' = (a - b) * zeta
                let t = a;
                let bb = t - b;
                (t + b, fqmul(z, bb))
            } else {
                // fwd: t = b*zeta ; a' = a + t ; b' = a - t
                let t = fqmul(z, b);
                (a + t, a - t)
            };

            out.porta.addr = st.j.resize::<U8>();
            out.porta.we = true;
            out.porta.wdata = wa;

            out.portb.addr = (st.j + st.len).resize::<U8>();
            out.portb.we = true;
            out.portb.wdata = wb;

            // advance indices
            let end_in_block = st.start + st.len;
            let next_j = st.j + u9(1);

            if next_j < end_in_block {
                ns.j = next_j;
                ns.phase = Phase::Read;
            } else {
                let next_start = st.start + (st.len << 1);

                if next_start < u9(N as u16) {
                    ns.start = next_start;
                    ns.j = next_start;

                    ns.k = if st.inverse { st.k - u9(1) } else { st.k + u9(1) };
                    ns.phase = Phase::Read;
                } else {
                    // stage done
                    if st.inverse {
                        if st.len == u9(128) {
                            ns.idx = u9(0);
                            ns.phase = Phase::FinalRead;
                        } else {
                            ns.len = st.len << 1;
                            ns.start = u9(0);
                            ns.j = u9(0);
                            ns.k = st.k - u9(1);
                            ns.phase = Phase::Read;
                        }
                    } else {
                        if st.len == u9(1) {
                            ns.phase = Phase::Done;
                        } else {
                            ns.len = st.len >> 1;
                            ns.start = u9(0);
                            ns.j = u9(0);
                            ns.k = st.k + u9(1);
                            ns.phase = Phase::Read;
                        }
                    }
                }
            }
        }

        Phase::FinalRead => {
            out.porta.addr = st.idx.resize::<U8>();
            out.porta.we = false;

            out.portb.addr = u8(0);
            out.portb.we = false;

            ns.phase = Phase::FinalWrite;
        }

        Phase::FinalWrite => {
            let a = inp.rdata_a;
            let prod: Wide = (s64(F as i128) * a.resize::<U64>()).resize::<U64>();
            let scaled = montgomery_reduce(prod);

            out.porta.addr = st.idx.resize::<U8>();
            out.porta.we = true;
            out.porta.wdata = scaled;

            out.portb.we = false;

            let next_idx = st.idx + u9(1);
            if next_idx < u9(N as u16) {
                ns.idx = next_idx;
                ns.phase = Phase::FinalRead;
            } else {
                ns.phase = Phase::Done;
            }
        }

        Phase::Done => {
            out.done = true;
        }
    }

    (ns, out)
}

// -----------------------------------------------------------------------------
// Software wrappers (demo/verify): emulate a dual-port 1-cycle-latency BRAM.
// No `for`/`while` keyword used.
// -----------------------------------------------------------------------------

#[inline(always)]
fn mem_read(mem: &[Coeff; N], addr: Bits<U8>) -> Coeff {
    mem[addr.raw() as usize]
}

#[inline(always)]
fn mem_write(mem: &mut [Coeff; N], req: MemReq) {
    if req.we {
        mem[req.addr.raw() as usize] = req.wdata;
    }
}

fn run_fsm(mem: &mut [Coeff; N], inverse: bool) {
    let mut st = NttState::default();
    let mut start = true;

    let mut pending_valid = false;
    let mut pending_a = u8(0);
    let mut pending_b = u8(0);

    let mut rdata_a = s32(0);
    let mut rdata_b = s32(0);

    let _ = (0usize..20_000usize).try_for_each(|_| {
        if pending_valid {
            rdata_a = mem_read(mem, pending_a);
            rdata_b = mem_read(mem, pending_b);
        } else {
            rdata_a = s32(0);
            rdata_b = s32(0);
        }

        let inp = NttIn { start, inverse, rdata_a, rdata_b };
        let (ns, out) = ntt_step(st, inp);
        st = ns;

        mem_write(mem, out.porta);
        mem_write(mem, out.portb);

        pending_valid = !out.porta.we;
        if pending_valid {
            pending_a = out.porta.addr;
            pending_b = out.portb.addr;
        }

        start = false;

        if out.done {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
}

/// Forward NTT (in-place) on i32 coefficients (for your current software Dilithium flow)
pub fn ntt(a: &mut [i32; N]) {
    let mut mem = [s32(0); N];
    a.iter().enumerate().for_each(|(i, &v)| {
        mem[i] = s32(v as i64);
    });

    run_fsm(&mut mem, false);

    a.iter_mut().enumerate().for_each(|(i, slot)| {
        *slot = mem[i].raw() as i32;
    });
}

/// Inverse NTT (invntt_tomont) (in-place) on i32 coefficients
pub fn intt(a: &mut [i32; N]) {
    let mut mem = [s32(0); N];
    a.iter().enumerate().for_each(|(i, &v)| {
        mem[i] = s32(v as i64);
    });

    run_fsm(&mut mem, true);

    a.iter_mut().enumerate().for_each(|(i, slot)| {
        *slot = mem[i].raw() as i32;
    });
}
