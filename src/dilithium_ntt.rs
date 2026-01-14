//Dilithium NTT/INTT hardware core in RHDL style (FSM + dual-port BRAM interface).
// Step function: NO for/while, fully FSM-based.
// Includes optional software wrappers that emulate 1-cycle BRAM latency.

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
fn b8(x: u8) -> Bits<U8> { bits(x as u128) }
#[inline(always)]
fn b9(x: u16) -> Bits<U9> { bits(x as u128) }

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

    pub len: Bits<U9>,     // fwd: 128..1 ; inv: 1..128
    pub start: Bits<U9>,   // block start
    pub j: Bits<U9>,       // current j
    pub k: Bits<U9>,       // zeta index (fwd inc, inv dec)

    pub idx: Bits<U9>,     // final scaling index (inv only)
}

#[inline(always)]
fn zeta_for_block(inverse: bool, k: Bits<U9>) -> Coeff {
    let idx = k.raw() as usize; // 0..255
    let z = ZETAS[idx] as i64;
    if inverse { s32(-z) } else { s32(z) }
}

#[inline(always)]
pub fn montgomery_reduce(a: Wide) -> Coeff {
    // Dilithium ref:
    // t = (int32_t)a * QINV;
    // t = (a - (int64_t)t*Q) >> 32;
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
/// - forward: CT butterfly
/// - inverse: GS butterfly + final scaling by F (invntt_tomont)
pub fn ntt_step(st: NttState, inp: NttIn) -> (NttState, NttOut) {
    let mut ns = st;
    let mut out = NttOut::default();

    out.busy = st.phase != Phase::Idle && st.phase != Phase::Done;
    out.done = false;

    match st.phase {
        Phase::Idle => {
            if inp.start {
                ns.inverse = inp.inverse;
                ns.start = b9(0);
                ns.j = b9(0);
                ns.idx = b9(0);

                // Dilithium ref:
                // fwd: len=128..1, k starts at 1 (ZETAS[0]=0)
                // inv: len=1..128, k starts at 255 and decrements
                if inp.inverse {
                    ns.len = b9(1);
                    ns.k = b9(255);
                } else {
                    ns.len = b9(128);
                    ns.k = b9(1);
                }

                ns.phase = Phase::Read;
            }
        }

        Phase::Read => {
            // read a=r[j], b=r[j+len]
            out.porta.addr = st.j.resize::<U8>();
            out.porta.we = false;

            out.portb.addr = (st.j + st.len).resize::<U8>();
            out.portb.we = false;

            ns.phase = Phase::Write;
        }

        Phase::Write => {
            let a = inp.rdata_a;
            let b = inp.rdata_b;

            let z = zeta_for_block(st.inverse, st.k);

            // Butterfly
            let (wa, wb) = if st.inverse {
                // GS:
                // a' = a + b
                // b' = (a - b) * zeta   (here zeta = -ZETAS[k])
                let t = a;
                let bb = t - b;
                (t + b, fqmul(z, bb))
            } else {
                // CT:
                // t = b * zeta
                // a' = a + t
                // b' = a - t
                let t = fqmul(z, b);
                (a + t, a - t)
            };

            // Write back
            out.porta.addr = st.j.resize::<U8>();
            out.porta.we = true;
            out.porta.wdata = wa;

            out.portb.addr = (st.j + st.len).resize::<U8>();
            out.portb.we = true;
            out.portb.wdata = wb;

            // Advance counters
            let endj = st.start + st.len; // exclusive
            let next_j = st.j + b9(1);

            if next_j == endj {
                // end of block
                let next_k = if st.inverse { st.k - b9(1) } else { st.k + b9(1) };
                let next_start = st.start + (st.len << 1);

                if next_start >= b9(N as u16) {
                    // end of stage
                    if st.inverse {
                        let next_len = st.len << 1;
                        if next_len > b9(128) {
                            // final scaling
                            ns.idx = b9(0);
                            ns.phase = Phase::FinalRead;
                        } else {
                            ns.len = next_len;
                            ns.start = b9(0);
                            ns.j = b9(0);
                            ns.k = next_k;
                            ns.phase = Phase::Read;
                        }
                    } else {
                        if st.len == b9(1) {
                            ns.phase = Phase::Done;
                        } else {
                            ns.len = st.len >> 1;
                            ns.start = b9(0);
                            ns.j = b9(0);
                            ns.k = next_k;
                            ns.phase = Phase::Read;
                        }
                    }
                } else {
                    // next block, same stage
                    ns.start = next_start;
                    ns.j = next_start;
                    ns.k = next_k;
                    ns.phase = Phase::Read;
                }
            } else {
                // continue block
                ns.j = next_j;
                ns.phase = Phase::Read;
            }
        }

        Phase::FinalRead => {
            // invntt_tomont: a[i] = montgomery_reduce(F * a[i])
            out.porta.addr = st.idx.resize::<U8>();
            out.porta.we = false;

            out.portb.addr = b8(0);
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

            let next_idx = st.idx + b9(1);
            if next_idx == b9(N as u16) {
                ns.phase = Phase::Done;
            } else {
                ns.idx = next_idx;
                ns.phase = Phase::FinalRead;
            }
        }

        Phase::Done => {
            out.done = true;
            out.busy = false;
            // ca la Kyber: revii în Idle când start e 0
            if !inp.start {
                ns.phase = Phase::Idle;
            }
        }
    }

    (ns, out)
}

// -----------------------------------------------------------------------------
// Optional software wrappers: emulate dual-port 1-cycle BRAM latency.
// -----------------------------------------------------------------------------
// Dacă nu vrei deloc “software wrapper”, poți șterge partea de mai jos fără
// să afectezi core-ul FSM.

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
    let mut pending_a = b8(0);
    let mut pending_b = b8(0);

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

        // reads happen when porta.we==false (in Read/FinalRead)
        pending_valid = !out.porta.we;
        if pending_valid {
            pending_a = out.porta.addr;
            pending_b = out.portb.addr;
        }

        start = false;

        if out.done { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
    });
}

/// Forward NTT (in-place) on i32 coefficients
pub fn ntt(a: &mut [i32; N]) {
    let mut mem = [s32(0); N];
    a.iter().enumerate().for_each(|(i, &v)| mem[i] = s32(v as i64));
    run_fsm(&mut mem, false);
    a.iter_mut().enumerate().for_each(|(i, slot)| *slot = mem[i].raw() as i32);
}

/// Inverse NTT (invntt_tomont) (in-place) on i32 coefficients
pub fn intt(a: &mut [i32; N]) {
    let mut mem = [s32(0); N];
    a.iter().enumerate().for_each(|(i, &v)| mem[i] = s32(v as i64));
    run_fsm(&mut mem, true);
    a.iter_mut().enumerate().for_each(|(i, slot)| *slot = mem[i].raw() as i32);
}
