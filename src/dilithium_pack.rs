use crate::dilithium_params::{DilithiumParams, N};
use crate::dilithium_poly::{Poly, PolyVec};
use crate::dilithium_rounding::norm_bound;

pub fn pack_poly_t1(a: &Poly) -> [u8; 320] {
    // 256 coeffs, 10 bits each
    let mut out = [0u8; 320];
    let mut bitpos = 0usize;
    for &c in &a.coeffs {
        let v = c as u32; // expect in [0, 2^10)
        for k in 0..10 {
            let b = ((v >> k) & 1) as u8;
            let byte = bitpos / 8;
            let bit = bitpos % 8;
            out[byte] |= b << bit;
            bitpos += 1;
        }
    }
    out
}

pub fn unpack_poly_t1(buf: &[u8; 320]) -> Poly {
    let mut a = Poly::default();
    let mut bitpos = 0usize;
    for i in 0..N {
        let mut v = 0u32;
        for k in 0..10 {
            let byte = bitpos / 8;
            let bit = bitpos % 8;
            let b = (buf[byte] >> bit) & 1;
            v |= (b as u32) << k;
            bitpos += 1;
        }
        a.coeffs[i] = v as i32;
    }
    a
}

pub fn pack_poly_t0(a: &Poly) -> [u8; 416] {
    // 13 bits each, store a0 in [0,2^13) by offsetting
    let mut out = [0u8; 416];
    let mut bitpos = 0usize;
    for &c in &a.coeffs {
        let v = (c + (1 << 12)) as u32;
        for k in 0..13 {
            let b = ((v >> k) & 1) as u8;
            let byte = bitpos / 8;
            let bit = bitpos % 8;
            out[byte] |= b << bit;
            bitpos += 1;
        }
    }
    out
}

pub fn unpack_poly_t0(buf: &[u8; 416]) -> Poly {
    let mut a = Poly::default();
    let mut bitpos = 0usize;
    for i in 0..N {
        let mut v = 0u32;
        for k in 0..13 {
            let byte = bitpos / 8;
            let bit = bitpos % 8;
            let b = (buf[byte] >> bit) & 1;
            v |= (b as u32) << k;
            bitpos += 1;
        }
        a.coeffs[i] = (v as i32) - (1 << 12);
    }
    a
}

pub fn pack_poly_eta<P: DilithiumParams>(a: &Poly) -> Vec<u8> {
    // eta=2: 3 bits for (eta - coeff) in [0..4]
    // eta=4: 4 bits for (eta - coeff) in [0..8]
    let mut out = vec![0u8; P::POLYETA_PACKEDBYTES];
    if P::ETA == 2 {
        let mut bitpos = 0usize;
        for &c in &a.coeffs {
            let t = (P::ETA - c) as u32; // 0..4
            for k in 0..3 {
                let b = ((t >> k) & 1) as u8;
                out[bitpos / 8] |= b << (bitpos % 8);
                bitpos += 1;
            }
        }
    } else {
        let mut bitpos = 0usize;
        for &c in &a.coeffs {
            let t = (P::ETA - c) as u32; // 0..8
            for k in 0..4 {
                let b = ((t >> k) & 1) as u8;
                out[bitpos / 8] |= b << (bitpos % 8);
                bitpos += 1;
            }
        }
    }
    out
}

pub fn unpack_poly_eta<P: DilithiumParams>(buf: &[u8]) -> Poly {
    let mut a = Poly::default();
    if P::ETA == 2 {
        let mut bitpos = 0usize;
        for i in 0..N {
            let mut t = 0u32;
            for k in 0..3 {
                let b = (buf[bitpos / 8] >> (bitpos % 8)) & 1;
                t |= (b as u32) << k;
                bitpos += 1;
            }
            a.coeffs[i] = P::ETA - (t as i32);
        }
    } else {
        let mut bitpos = 0usize;
        for i in 0..N {
            let mut t = 0u32;
            for k in 0..4 {
                let b = (buf[bitpos / 8] >> (bitpos % 8)) & 1;
                t |= (b as u32) << k;
                bitpos += 1;
            }
            a.coeffs[i] = P::ETA - (t as i32);
        }
    }
    a
}

pub fn pack_poly_z<P: DilithiumParams>(a: &Poly) -> Vec<u8> {
    // gamma1=2^17 -> 18 bits, gamma1=2^19 -> 20 bits
    let bits = if P::GAMMA1 == (1 << 17) { 18 } else { 20 };
    let mut out = vec![0u8; P::POLYZ_PACKEDBYTES];
    let mut bitpos = 0usize;

    for &c in &a.coeffs {
        let t = ((P::GAMMA1 - 1) - c) as u32; // match sample mapping
        for k in 0..bits {
            let b = ((t >> k) & 1) as u8;
            out[bitpos / 8] |= b << (bitpos % 8);
            bitpos += 1;
        }
    }
    out
}

pub fn unpack_poly_z<P: DilithiumParams>(buf: &[u8]) -> Poly {
    let bits = if P::GAMMA1 == (1 << 17) { 18 } else { 20 };
    let mut a = Poly::default();
    let mut bitpos = 0usize;

    for i in 0..N {
        let mut t = 0u32;
        for k in 0..bits {
            let b = (buf[bitpos / 8] >> (bitpos % 8)) & 1;
            t |= (b as u32) << k;
            bitpos += 1;
        }
        a.coeffs[i] = (P::GAMMA1 - 1) - (t as i32);
    }
    a
}

pub fn pack_poly_w1<P: DilithiumParams>(a1: &Poly) -> Vec<u8> {
    // gamma2: modes 2/3 -> 6 bits (0..43) => 192 bytes
    // mode 5 -> 4 bits (0..15) => 128 bytes
    let bits = if P::POLYW1_PACKEDBYTES == 192 { 6 } else { 4 };
    let mut out = vec![0u8; P::POLYW1_PACKEDBYTES];
    let mut bitpos = 0usize;

    for &c in &a1.coeffs {
        let v = c as u32;
        for k in 0..bits {
            let b = ((v >> k) & 1) as u8;
            out[bitpos / 8] |= b << (bitpos % 8);
            bitpos += 1;
        }
    }
    out
}

// MODIFICARE: Am adăugat `const K: usize` în semnătură pentru a putea folosi PolyVec<K>
pub fn polyvec_w1_bytes<P: DilithiumParams, const K: usize>(w1: &PolyVec<K>) -> Vec<u8> {
    // Folosim K explicit, nu P::K
    let mut out = Vec::with_capacity(K * P::POLYW1_PACKEDBYTES);
    for i in 0..K {
        out.extend_from_slice(&pack_poly_w1::<P>(&w1.v[i]));
    }
    out
}

// MODIFICARE: Generic `const K` pentru consistență, deși corpul e gol
pub fn hint_weight<const K: usize>(h: &PolyVec<K>) -> usize {
    let _ = h;
    0
}

// MODIFICARE: Am adăugat `const K: usize`
pub fn pack_hints<P: DilithiumParams, const K: usize>(h: &PolyVec<K>) -> Vec<u8> {
    let mut out = vec![0u8; P::OMEGA + K];
    let mut k_idx = 0usize; // redenumit pentru a nu intra in conflict cu K constant

    for i in 0..K {
        for j in 0..N {
            if h.v[i].coeffs[j] != 0 {
                if k_idx >= P::OMEGA { break; }
                out[k_idx] = j as u8;
                k_idx += 1;
            }
        }
        out[P::OMEGA + i] = k_idx as u8;
    }
    out
}

// MODIFICARE: Am adăugat `const K: usize`
pub fn unpack_hints<P: DilithiumParams, const K: usize>(buf: &[u8]) -> Option<PolyVec<K>> {
    if buf.len() != P::OMEGA + K { return None; }
    
    // Folosim explicit K pentru default
    let mut h = PolyVec::<K>::default();
    
    let mut k0 = 0usize;
    for i in 0..K {
        let k1 = buf[P::OMEGA + i] as usize;
        if k1 < k0 || k1 > P::OMEGA { return None; }
        for j in k0..k1 {
            let pos = buf[j] as usize;
            if pos >= N { return None; }
            h.v[i].coeffs[pos] = 1;
        }
        k0 = k1;
    }
    Some(h)
}

// Check norms
pub fn poly_check_norm(a: &Poly, bound: i32) -> bool {
    for &c in &a.coeffs {
        if norm_bound(c) >= bound { return false; }
    }
    true
}