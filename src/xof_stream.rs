// Incremental SHAKE stream wrapper (software) built on top of Keccak-f[1600].
// - Kyber/Dilithium sampling in "hardware style" wants a byte-stream:
//     absorb(seed...) once, then squeeze bytes incrementally.
// - Your current shake.rs is "one-shot" (shake256(input, out)), which is fine,
//   but sampling_rhdl FSM becomes MUCH easier to test if it consumes a stream.
//
// This file provides ShakeStream::shake128(...) and ShakeStream::shake256(...)
// with next_u8() / fill_bytes().

#![allow(dead_code)]

use crate::keccak::keccak_f1600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShakeKind {
    Shake128,
    Shake256,
}

#[derive(Clone, Debug)]
pub struct ShakeStream {
    kind: ShakeKind,
    rate: usize, // 168 for SHAKE128, 136 for SHAKE256
    state: [u64; 25],
    buf: [u8; 168], // max(rate)
    pos: usize,     // next read position inside buf
}

impl ShakeStream {
    /// Create a SHAKE128 stream: absorb input, then ready to squeeze bytes.
    pub fn shake128(input: &[u8]) -> Self {
        Self::new(ShakeKind::Shake128, 168, 0x1F, input)
    }

    /// Create a SHAKE256 stream: absorb input, then ready to squeeze bytes.
    pub fn shake256(input: &[u8]) -> Self {
        Self::new(ShakeKind::Shake256, 136, 0x1F, input)
    }

    pub fn kind(&self) -> ShakeKind {
        self.kind
    }

    /// Get next byte from XOF stream.
    #[inline(always)]
    pub fn next_u8(&mut self) -> u8 {
        if self.pos >= self.rate {
            // Need next block
            keccak_f1600(&mut self.state);
            self.squeeze_block_into_buf();
            self.pos = 0;
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }

    /// Fill `out` with bytes from the stream.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for o in out.iter_mut() {
            *o = self.next_u8();
        }
    }

    // ------------------------------------------------------------------------
    // Internal sponge logic
    // ------------------------------------------------------------------------

    fn new(kind: ShakeKind, rate: usize, domain: u8, input: &[u8]) -> Self {
        debug_assert!(rate == 168 || rate == 136);
        let mut st = [0u64; 25];
        let mut off = 0usize;

        // Absorb full blocks
        while input.len().saturating_sub(off) >= rate {
            Self::xor_bytes_into_state(&mut st, &input[off..off + rate], rate);
            keccak_f1600(&mut st);
            off += rate;
        }

        // Final block with padding (no heap)
        let rem = input.len() - off;
        let mut block = [0u8; 168]; // max rate
        if rem > 0 {
            block[..rem].copy_from_slice(&input[off..]);
        }
        block[rem] ^= domain;
        block[rate - 1] ^= 0x80;

        Self::xor_bytes_into_state(&mut st, &block[..rate], rate);
        keccak_f1600(&mut st);

        // Initialize output buffer with first squeezed block
        let mut me = Self {
            kind,
            rate,
            state: st,
            buf: [0u8; 168],
            pos: 0,
        };
        me.squeeze_block_into_buf();
        me
    }

    #[inline(always)]
    fn xor_bytes_into_state(state: &mut [u64; 25], block: &[u8], rate: usize) {
        // Little-endian lanes
        for i in 0..rate {
            let lane = i / 8;
            let shift = (i % 8) * 8;
            state[lane] ^= (block[i] as u64) << shift;
        }
    }

    #[inline(always)]
    fn squeeze_block_into_buf(&mut self) {
        // Export the "rate" bytes from state into buf[0..rate]
        for i in 0..self.rate {
            let lane = self.state[i / 8];
            self.buf[i] = ((lane >> (8 * (i % 8))) & 0xFF) as u8;
        }
        // buf beyond rate is don't-care
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Quick sanity: SHAKE256("") first 32 bytes (matches known test vectors).
    // We avoid hardcoding a long vector here; instead we compare with your shake.rs one-shot.
    #[test]
    fn stream_matches_oneshot_shake256() {
        let mut stream = ShakeStream::shake256(&[]);
        let mut a = [0u8; 64];
        stream.fill_bytes(&mut a);

        let mut b = [0u8; 64];
        crate::shake::shake256(&[], &mut b);

        assert_eq!(a, b);
    }

    #[test]
    fn stream_matches_oneshot_shake128() {
        let mut stream = ShakeStream::shake128(b"abc");
        let mut a = [0u8; 100];
        stream.fill_bytes(&mut a);

        let mut b = [0u8; 100];
        crate::shake::shake128(b"abc", &mut b);

        assert_eq!(a, b);
    }
}
