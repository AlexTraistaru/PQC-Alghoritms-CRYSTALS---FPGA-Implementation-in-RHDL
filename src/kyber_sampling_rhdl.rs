
// RHDL Bits: folosește bits(u128) și .raw() pentru conversii.

#![allow(dead_code)]
#![allow(non_snake_case)]

use rhdl::prelude::*;

use crate::kyber_arith::Coeff;
use crate::kyber_params::{KYBER_N, KYBER_Q};

// ------------------------------
// Streaming interface (generic)
// ------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub struct ByteStreamIn {
    pub valid: bool,
    pub data: Bits<U8>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ByteStreamOut {
    pub ready: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CoeffWrite {
    pub we: bool,
    pub addr: Bits<U8>, // 0..255
    pub data: Coeff,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SampleOut {
    pub in_stream: ByteStreamOut,
    pub wr: CoeffWrite,
    pub done: bool,
}

#[inline(always)]
fn u8_from_bits(x: Bits<U8>) -> u8 {
    x.raw() as u8
}

#[inline(always)]
fn s16(x: i32) -> Coeff {
    signed::<U16>(x as i128)
}

#[inline(always)]
fn j_is_last(j: Bits<U8>) -> bool {
    // KYBER_N = 256 => ultimul index valid este 255
    (j.raw() as u8) == 255u8
}

// ------------------------------
// ParseUniform: rejection sampler
// ------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ParsePhase {
    #[default]
    Collect,
    EmitSecond,
    Done,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ParseUniformState {
    pub phase: ParsePhase,

    /// output coefficient index 0..255
    pub j: Bits<U8>,

    /// 3-byte buffer collection
    pub buf0: Bits<U8>,
    pub buf1: Bits<U8>,
    pub buf2: Bits<U8>,
    pub buf_cnt: Bits<U2>, // 0,1,2

    /// pending second coefficient (when both d1 and d2 were accepted)
    pub pend_valid: bool,
    pub pend_val: u16,
}

impl ParseUniformState {
    #[inline(always)]
    pub fn reset() -> Self {
        Self::default()
    }
}

pub fn parse_uniform_step(mut st: ParseUniformState, inp: ByteStreamIn) -> (ParseUniformState, SampleOut) {
    let mut out = SampleOut::default();
    out.in_stream.ready = false;
    out.wr.we = false;
    out.done = false;

    if st.phase == ParsePhase::Done {
        out.done = true;
        return (st, out);
    }

    // -------------------------------------------------------------------------
    // Emit pending second coefficient (does NOT consume input bytes)
    // -------------------------------------------------------------------------
    if st.phase == ParsePhase::EmitSecond {
        if st.pend_valid {
            out.wr.we = true;
            out.wr.addr = st.j;
            out.wr.data = s16(st.pend_val as i32);
            st.pend_valid = false;

            if j_is_last(st.j) {
                st.phase = ParsePhase::Done;
            } else {
                let j_u8: u8 = st.j.raw() as u8;
                st.j = bits(j_u8.wrapping_add(1) as u128);
                st.phase = ParsePhase::Collect;
            }
        } else {
            // dacă ajungem aici, revenim în Collect (safety)
            st.phase = ParsePhase::Collect;
        }
        if st.phase == ParsePhase::Done {
            out.done = true;
        }
        return (st, out);
    }

    // -------------------------------------------------------------------------
    // Collect 3 bytes, produce up to 2 coefficients
    // -------------------------------------------------------------------------
    if st.phase == ParsePhase::Collect {
        out.in_stream.ready = true;

        if inp.valid {
            let b = inp.data;

            let cnt: u8 = st.buf_cnt.raw() as u8;
            if cnt == 0 {
                st.buf0 = b;
                st.buf_cnt = bits(1u128);
                return (st, out);
            } else if cnt == 1 {
                st.buf1 = b;
                st.buf_cnt = bits(2u128);
                return (st, out);
            } else {
                st.buf2 = b;
                st.buf_cnt = bits(0u128);

                // parse 3 bytes -> two 12-bit values
                let b0 = u8_from_bits(st.buf0) as u32;
                let b1 = u8_from_bits(st.buf1) as u32;
                let b2 = u8_from_bits(st.buf2) as u32;

                let d1 = (b0 | (b1 << 8)) & 0x0FFF;
                let d2 = ((b1 >> 4) | (b2 << 4)) & 0x0FFF;

                let q = KYBER_Q as u32;
                let accepted1 = d1 < q;
                let accepted2 = d2 < q;

                // Try write d1 first
                if accepted1 {
                    out.wr.we = true;
                    out.wr.addr = st.j;
                    out.wr.data = s16(d1 as i32);

                    if j_is_last(st.j) {
                        st.phase = ParsePhase::Done;
                        out.done = true;
                        return (st, out);
                    } else {
                        let j_u8: u8 = st.j.raw() as u8;
                        st.j = bits(j_u8.wrapping_add(1) as u128);

                        // If also accept d2, emit next cycle (no input consume)
                        if accepted2 {
                            st.pend_valid = true;
                            st.pend_val = d2 as u16;
                            st.phase = ParsePhase::EmitSecond;
                        }
                        return (st, out);
                    }
                }

                // If d1 rejected, try d2
                if accepted2 {
                    out.wr.we = true;
                    out.wr.addr = st.j;
                    out.wr.data = s16(d2 as i32);

                    if j_is_last(st.j) {
                        st.phase = ParsePhase::Done;
                        out.done = true;
                    } else {
                        let j_u8: u8 = st.j.raw() as u8;
                        st.j = bits(j_u8.wrapping_add(1) as u128);
                    }
                    return (st, out);
                }

                // none accepted -> stay Collect
                return (st, out);
            }
        }

        return (st, out);
    }

    (st, out)
}

// ------------------------------
// CBD eta=2 (Kyber noise sampler)
// ------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Cbd2Phase {
    #[default]
    Collect,
    Emit,
    Done,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Cbd2State {
    pub phase: Cbd2Phase,

    pub j: Bits<U8>,       // coefficient index 0..255
    pub buf_cnt: Bits<U2>, // 0..3
    pub b0: Bits<U8>,
    pub b1: Bits<U8>,
    pub b2: Bits<U8>,
    pub b3: Bits<U8>,

    pub d: u32,
    pub sub: Bits<U3>, // 0..7
}

pub fn cbd2_step(mut st: Cbd2State, inp: ByteStreamIn) -> (Cbd2State, SampleOut) {
    let mut out = SampleOut::default();
    out.in_stream.ready = false;
    out.wr.we = false;
    out.done = false;

    if st.phase == Cbd2Phase::Done {
        out.done = true;
        return (st, out);
    }

    if st.phase == Cbd2Phase::Collect {
        out.in_stream.ready = true;
        if inp.valid {
            let cnt: u8 = st.buf_cnt.raw() as u8;
            if cnt == 0 {
                st.b0 = inp.data;
                st.buf_cnt = bits(1u128);
            } else if cnt == 1 {
                st.b1 = inp.data;
                st.buf_cnt = bits(2u128);
            } else if cnt == 2 {
                st.b2 = inp.data;
                st.buf_cnt = bits(3u128);
            } else {
                st.b3 = inp.data;
                st.buf_cnt = bits(0u128);

                let b0: u8 = st.b0.raw() as u8;
                let b1: u8 = st.b1.raw() as u8;
                let b2: u8 = st.b2.raw() as u8;
                let b3: u8 = st.b3.raw() as u8;

                let t: u32 = (b0 as u32)
                    | ((b1 as u32) << 8)
                    | ((b2 as u32) << 16)
                    | ((b3 as u32) << 24);

                let mut d = t & 0x5555_5555;
                d = d.wrapping_add((t >> 1) & 0x5555_5555);

                st.d = d;
                st.sub = bits(0u128);
                st.phase = Cbd2Phase::Emit;
            }
        }
        return (st, out);
    }

    if st.phase == Cbd2Phase::Emit {
        let sub: u8 = st.sub.raw() as u8;

        let a = ((st.d >> (4 * sub)) & 0x3) as i16;
        let b = ((st.d >> (4 * sub + 2)) & 0x3) as i16;
        let coeff = a - b;

        out.wr.we = true;
        out.wr.addr = st.j;
        out.wr.data = s16(coeff as i32);

        // Advance j with saturation at last element
        if j_is_last(st.j) {
            st.phase = Cbd2Phase::Done;
            out.done = true;
            return (st, out);
        } else {
            let j_u8: u8 = st.j.raw() as u8;
            st.j = bits(j_u8.wrapping_add(1) as u128);
        }

        // subcounter
        if sub == 7 {
            st.sub = bits(0u128);
            st.phase = Cbd2Phase::Collect;
        } else {
            st.sub = bits((sub + 1) as u128);
        }
        return (st, out);
    }

    (st, out)
}

// ------------------------------
// CBD eta=3 (Kyber noise sampler)
// ------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Cbd3Phase {
    #[default]
    Collect,
    Emit,
    Done,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Cbd3State {
    pub phase: Cbd3Phase,

    pub j: Bits<U8>,
    pub buf_cnt: Bits<U2>, // 0..2
    pub b0: Bits<U8>,
    pub b1: Bits<U8>,
    pub b2: Bits<U8>,

    pub d: u32,
    pub sub: Bits<U2>, // 0..3
}

pub fn cbd3_step(mut st: Cbd3State, inp: ByteStreamIn) -> (Cbd3State, SampleOut) {
    let mut out = SampleOut::default();
    out.in_stream.ready = false;
    out.wr.we = false;
    out.done = false;

    if st.phase == Cbd3Phase::Done {
        out.done = true;
        return (st, out);
    }

    if st.phase == Cbd3Phase::Collect {
        out.in_stream.ready = true;
        if inp.valid {
            let cnt: u8 = st.buf_cnt.raw() as u8;
            if cnt == 0 {
                st.b0 = inp.data;
                st.buf_cnt = bits(1u128);
            } else if cnt == 1 {
                st.b1 = inp.data;
                st.buf_cnt = bits(2u128);
            } else {
                st.b2 = inp.data;
                st.buf_cnt = bits(0u128);

                let t: u32 =
                    (u8_from_bits(st.b0) as u32) |
                    ((u8_from_bits(st.b1) as u32) << 8) |
                    ((u8_from_bits(st.b2) as u32) << 16);

                let mut d = t & 0x0024_9249;
                d = d.wrapping_add((t >> 1) & 0x0024_9249);
                d = d.wrapping_add((t >> 2) & 0x0024_9249);

                st.d = d;
                st.sub = bits(0u128);
                st.phase = Cbd3Phase::Emit;
            }
        }
        return (st, out);
    }

    if st.phase == Cbd3Phase::Emit {
        let sub: u8 = st.sub.raw() as u8;

        let a = ((st.d >> (6 * sub)) & 0x7) as i16;
        let b = ((st.d >> (6 * sub + 3)) & 0x7) as i16;
        let coeff = a - b;

        out.wr.we = true;
        out.wr.addr = st.j;
        out.wr.data = s16(coeff as i32);

        if j_is_last(st.j) {
            st.phase = Cbd3Phase::Done;
            out.done = true;
            return (st, out);
        } else {
            let j_u8: u8 = st.j.raw() as u8;
            st.j = bits(j_u8.wrapping_add(1) as u128);
        }

        if sub == 3 {
            st.sub = bits(0u128);
            st.phase = Cbd3Phase::Collect;
        } else {
            st.sub = bits((sub + 1) as u128);
        }
        return (st, out);
    }

    (st, out)
}
