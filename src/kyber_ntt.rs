#![allow(non_snake_case)]
#![allow(dead_code)]

use rhdl::prelude::*;
use crate::kyber_arith::{barrett_reduce, fqmul};
use crate::kyber_params::ZETAS;

/// f = inv128 * R^2 mod q = 1441 (Kyber reference invntt final factor)
pub const INVNTT_F: i32 = 1441;

/// Coefficient types
pub type Coeff = SignedBits<U16>;
pub type Wide = SignedBits<U32>;

#[inline(always)]
fn u9(x: u16) -> Bits<U9> {
    bits(x as u128)
}
#[inline(always)]
fn u8(x: u8) -> Bits<U8> {
    bits(x as u128)
}
#[inline(always)]
fn s16(x: i32) -> Coeff {
    signed::<U16>(x as i128)
}

#[inline(always)]
fn zeta_from_k(k: Bits<U8>) -> Coeff {
    // ZETAS has 128 entries (0..127).
    let idx = k.raw() as usize;
    s16(ZETAS[idx] as i32)
}

// -------------------------------------------------------
// BRAM / MEM interface + FSM NTT core (2-phase butterfly)
// -------------------------------------------------------

/// Dual-port memory request (simple BRAM style)
#[derive(Copy, Clone, Default)]
pub struct MemReq {
    pub addr: Bits<U8>,
    pub we: bool,
    pub wdata: Coeff,
}

/// NTT command inputs
#[derive(Copy, Clone, Default)]
pub struct NttIn {
    pub start: bool,
    pub inverse: bool,
    pub rdata_a: Coeff,
    pub rdata_b: Coeff,
}

/// NTT outputs
#[derive(Copy, Clone, Default)]
pub struct NttOut {
    pub busy: bool,
    pub done: bool,
    pub porta: MemReq,
    pub portb: MemReq,
}

/// FSM phases
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
    fn default() -> Self {
        Phase::Idle
    }
}

/// State for the NTT engine
#[derive(Copy, Clone, Default)]
pub struct NttState {
    pub phase: Phase,

    // transform parameters
    pub inverse: bool,

    // loop counters
    pub len: Bits<U9>,   // 2..128
    pub start: Bits<U9>, // 0..255
    pub j: Bits<U9>,     // 0..255
    pub k: Bits<U8>,     // twiddle index (block-wise)

    // final scaling index (invntt)
    pub idx: Bits<U9>,
}

/// One-cycle step of the FSM.
///
/// IMPORTANT correctness details (Kyber reference):
/// - Twiddle index k changes ONCE PER BLOCK (not per butterfly).
/// - invntt uses `b2 = fqmul(zeta, b - t)` (not `t - b`).
pub fn ntt_step(st: NttState, inp: NttIn) -> (NttState, NttOut) {
    let mut ns = st;
    let mut out = NttOut::default();

    out.busy = st.phase != Phase::Idle && st.phase != Phase::Done;

    match st.phase {
        Phase::Idle => {
            out.done = false;
            if inp.start {
                ns.inverse = inp.inverse;

                if inp.inverse {
                    ns.len = u9(2);
                    ns.k = u8(127);
                } else {
                    ns.len = u9(128);
                    ns.k = u8(1);
                }

                ns.start = u9(0);
                ns.j = u9(0);
                ns.idx = u9(0);
                ns.phase = Phase::Read;
            }
        }

        Phase::Read => {
            // Issue BRAM reads for a=r[j] and b=r[j+len].
            out.porta.addr = st.j.resize::<U8>();
            out.portb.addr = (st.j + st.len).resize::<U8>();
            out.porta.we = false;
            out.portb.we = false;
            ns.phase = Phase::Write;
        }

        Phase::Write => {
            // Data arrives now.
            let a = inp.rdata_a;
            let b = inp.rdata_b;

            let z = zeta_from_k(st.k);

            // Butterfly.
            let (new_a, new_b) = if st.inverse {
                // invntt (Gentleman–Sande):
                // t = a
                // a = barrett_reduce(t + b)
                // b = fqmul(zeta, b - t)
                let t = a;
                let a2 = barrett_reduce(t + b);
                let b2 = fqmul(z, b - t);
                (a2, b2)
            } else {
                // ntt (Cooley–Tukey):
                // t = fqmul(zeta, b)
                // b = a - t
                // a = a + t
                let t = fqmul(z, b);
                (a + t, a - t)
            };

            // Write back.
            out.porta.addr = st.j.resize::<U8>();
            out.porta.we = true;
            out.porta.wdata = new_a;

            out.portb.addr = (st.j + st.len).resize::<U8>();
            out.portb.we = true;
            out.portb.wdata = new_b;

            // Advance loop counters.
            let endj = st.start + st.len; // exclusive
            let next_j = st.j + u9(1);

            if next_j == endj {
                // Finished this block => advance to next block and advance twiddle index.
                let next_k = if st.inverse { st.k - u8(1) } else { st.k + u8(1) };
                let next_start = st.start + (st.len << 1);

                if next_start >= u9(256) {
                    // Finished this stage.
                    if st.inverse {
                        let next_len = st.len << 1;
                        if next_len > u9(128) {
                            // Final scaling by INVNTT_F.
                            ns.phase = Phase::FinalRead;
                            ns.idx = u9(0);
                        } else {
                            ns.len = next_len;
                            ns.start = u9(0);
                            ns.j = u9(0);
                            ns.k = next_k;
                            ns.phase = Phase::Read;
                        }
                    } else {
                        let next_len = st.len >> 1;
                        if next_len < u9(2) {
                            ns.phase = Phase::Done;
                        } else {
                            ns.len = next_len;
                            ns.start = u9(0);
                            ns.j = u9(0);
                            ns.k = next_k;
                            ns.phase = Phase::Read;
                        }
                    }
                } else {
                    // Next block, same stage.
                    ns.start = next_start;
                    ns.j = next_start;
                    ns.k = next_k;
                    ns.phase = Phase::Read;
                }
            } else {
                // Continue this block.
                ns.j = next_j;
                ns.phase = Phase::Read;
            }
        }

        Phase::FinalRead => {
            // invntt final multiply by f on each coefficient.
            out.porta.addr = st.idx.resize::<U8>();
            out.porta.we = false;
            out.portb.we = false;
            ns.phase = Phase::FinalWrite;
        }

        Phase::FinalWrite => {
            let x = inp.rdata_a;
            let f = s16(INVNTT_F);
            let y = fqmul(x, f);

            out.porta.addr = st.idx.resize::<U8>();
            out.porta.we = true;
            out.porta.wdata = y;

            let next = st.idx + u9(1);
            if next == u9(256) {
                ns.phase = Phase::Done;
            } else {
                ns.idx = next;
                ns.phase = Phase::FinalRead;
            }
        }

        Phase::Done => {
            out.done = true;
            out.busy = false;
            // Return to idle after start deassert (simple level handshake).
            if !inp.start {
                ns.phase = Phase::Idle;
            }
        }
    }

    (ns, out)
}
