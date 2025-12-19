use crate::dilithium_params::{N, Q};
use crate::dilithium_reduce::{add_mod, sub_mod, mul_mod, mod_q};
use crate::dilithium_ntt::{ntt, intt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self { Self { coeffs: [0; N] } }
}

impl Poly {
    pub fn reduce(&mut self) {
        for c in &mut self.coeffs {
            *c = mod_q(*c as i64);
        }
    }

    pub fn caddq(&mut self) {
        for c in &mut self.coeffs {
            if *c < 0 { *c += Q; }
        }
    }

    pub fn add_assign(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = add_mod(self.coeffs[i], b.coeffs[i]);
        }
    }

    pub fn sub_assign(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = sub_mod(self.coeffs[i], b.coeffs[i]);
        }
    }

    pub fn shiftl(&mut self, d: usize) {
        for i in 0..N {
            self.coeffs[i] = mod_q((self.coeffs[i] as i64) << d);
        }
    }

    pub fn ntt(&mut self) { ntt(&mut self.coeffs); }
    pub fn intt(&mut self) { intt(&mut self.coeffs); }

    pub fn pointwise_mul(a: &Poly, b: &Poly) -> Poly {
        let mut r = Poly::default();
        for i in 0..N {
            r.coeffs[i] = mul_mod(a.coeffs[i], b.coeffs[i]);
        }
        r
    }

    pub fn mul_naive(a: &Poly, b: &Poly) -> Poly {
        // Negacyclic mod (x^N + 1)
        let mut t = [0i64; 2 * N];
        for i in 0..N {
            for j in 0..N {
                t[i + j] += (a.coeffs[i] as i64) * (b.coeffs[j] as i64);
            }
        }
        let mut r = Poly::default();
        for i in 0..N {
            let v = t[i] - t[i + N];
            r.coeffs[i] = mod_q(v);
        }
        r
    }

    pub fn mul_ntt(a: &Poly, b: &Poly) -> Poly {
        let mut fa = *a;
        let mut fb = *b;
        fa.ntt();
        fb.ntt();
        let mut fc = Poly::pointwise_mul(&fa, &fb);
        fc.intt();
        fc.reduce();
        fc
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyVec<const DIM: usize> {
    pub v: [Poly; DIM],
}
impl<const DIM: usize> Default for PolyVec<DIM> {
    fn default() -> Self { Self { v: core::array::from_fn(|_| Poly::default()) } }
}

impl<const DIM: usize> PolyVec<DIM> {
    pub fn ntt(&mut self) { for p in &mut self.v { p.ntt(); } }
    pub fn intt(&mut self) { for p in &mut self.v { p.intt(); } }

    pub fn add_assign(&mut self, b: &Self) {
        for i in 0..DIM { self.v[i].add_assign(&b.v[i]); }
    }
    pub fn sub_assign(&mut self, b: &Self) {
        for i in 0..DIM { self.v[i].sub_assign(&b.v[i]); }
    }

    pub fn pointwise_acc(a: &PolyVec<DIM>, b: &PolyVec<DIM>) -> Poly {
        let mut acc = Poly::default();
        for i in 0..DIM {
            let t = Poly::pointwise_mul(&a.v[i], &b.v[i]);
            acc.add_assign(&t);
        }
        acc
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PolyMat<const K: usize, const L: usize> {
    pub m: [[Poly; L]; K],
}
impl<const K: usize, const L: usize> Default for PolyMat<K, L> {
    fn default() -> Self {
        Self { m: core::array::from_fn(|_| core::array::from_fn(|_| Poly::default())) }
    }
}
