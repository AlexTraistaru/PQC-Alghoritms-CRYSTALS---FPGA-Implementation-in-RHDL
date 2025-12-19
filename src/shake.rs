use crate::keccak::keccak_f1600;

fn absorb(rate: usize, input: &[u8], domain: u8) -> [u64; 25] {
    let mut st = [0u64; 25];
    let mut off = 0usize;

    while input.len() - off >= rate {
        for i in 0..(rate / 8) {
            let mut lane = 0u64;
            for b in 0..8 {
                lane |= (input[off + 8 * i + b] as u64) << (8 * b);
            }
            st[i] ^= lane;
        }
        keccak_f1600(&mut st);
        off += rate;
    }

    // last block
    let mut block = vec![0u8; rate];
    block[..(input.len() - off)].copy_from_slice(&input[off..]);
    block[input.len() - off] ^= domain;
    block[rate - 1] ^= 0x80;

    for i in 0..(rate / 8) {
        let mut lane = 0u64;
        for b in 0..8 {
            lane |= (block[8 * i + b] as u64) << (8 * b);
        }
        st[i] ^= lane;
    }
    keccak_f1600(&mut st);
    st
}

fn squeeze(rate: usize, mut st: [u64; 25], out: &mut [u8]) {
    let mut produced = 0usize;
    while produced < out.len() {
        let take = core::cmp::min(rate, out.len() - produced);
        for i in 0..take {
            let lane = st[i / 8];
            out[produced + i] = ((lane >> (8 * (i % 8))) & 0xFF) as u8;
        }
        produced += take;
        if produced < out.len() {
            keccak_f1600(&mut st);
        }
    }
}

pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let st = absorb(136, input, 0x06);
    let mut out = [0u8; 32];
    squeeze(136, st, &mut out);
    out
}

pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    let st = absorb(72, input, 0x06);
    let mut out = [0u8; 64];
    squeeze(72, st, &mut out);
    out
}

pub fn shake128(input: &[u8], out: &mut [u8]) {
    let st = absorb(168, input, 0x1F);
    squeeze(168, st, out);
}

pub fn shake256(input: &[u8], out: &mut [u8]) {
    let st = absorb(136, input, 0x1F);
    squeeze(136, st, out);
}
