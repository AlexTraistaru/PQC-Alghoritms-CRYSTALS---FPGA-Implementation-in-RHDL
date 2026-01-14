// Dilithium poly / polyvec / polymat "glue" types.

use core::fmt;

use crate::dilithium_params::{N, Q};
use crate::dilithium_reduce::{add_mod, sub_mod, mod_q, mont_fqmul};
use crate::dilithium_ntt::{ntt, intt};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0i32; N] }
    }
}

impl fmt::Debug for Poly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print only a small prefix so logs stay readable
        f.debug_struct("Poly")
            .field("coeffs[0..8]", &&self.coeffs[0..8])
            .finish()
    }
}

impl Poly {
    /// Reduce coeffs into [0, q)
    pub fn reduce(&mut self) {
        self.coeffs
            .iter_mut()
            .for_each(|c| *c = mod_q(*c as i64));
    }

    /// self += other (mod q)
    pub fn add_assign(&mut self, other: &Poly) {
        self.coeffs
            .iter_mut()
            .zip(other.coeffs.iter())
            .for_each(|(a, &b)| *a = add_mod(*a, b));
    }

    /// self -= other (mod q)
    pub fn sub_assign(&mut self, other: &Poly) {
        self.coeffs
            .iter_mut()
            .zip(other.coeffs.iter())
            .for_each(|(a, &b)| *a = sub_mod(*a, b));
    }

    /// Shift left by d bits (mod q). Used in verify path (t1 << D).
    pub fn shiftl(&mut self, d: usize) {
        self.coeffs
            .iter_mut()
            .for_each(|c| *c = mod_q((*c as i64) << d));
    }

    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    pub fn intt(&mut self) {
        intt(&mut self.coeffs);
    }

    /// Pointwise multiplication in NTT domain:
    /// MUST be Montgomery multiply.
    pub fn pointwise_mul(a: &Poly, b: &Poly) -> Poly {
        let coeffs = core::array::from_fn(|i| mont_fqmul(a.coeffs[i], b.coeffs[i]));
        Poly { coeffs }
    }

    /// Optional helper: center into [-q/2, q/2]
    #[allow(dead_code)]
    pub fn center_coeff(x: i32) -> i32 {
        let mut t = x % Q;
        if t < 0 { t += Q; }
        if t > Q / 2 { t -= Q; }
        t
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PolyVec<const DIM: usize> {
    pub v: [Poly; DIM],
}

impl<const DIM: usize> Default for PolyVec<DIM> {
    fn default() -> Self {
        Self { v: core::array::from_fn(|_| Poly::default()) }
    }
}

impl<const DIM: usize> fmt::Debug for PolyVec<DIM> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same idea: keep it small
        f.debug_struct("PolyVec")
            .field("dim", &DIM)
            .field("v[0]", &self.v.get(0))
            .finish()
    }
}

impl<const DIM: usize> PolyVec<DIM> {
    pub fn reduce(&mut self) {
        self.v.iter_mut().for_each(|p| p.reduce());
    }

    pub fn add_assign(&mut self, other: &PolyVec<DIM>) {
        self.v
            .iter_mut()
            .zip(other.v.iter())
            .for_each(|(a, b)| a.add_assign(b));
    }

    pub fn sub_assign(&mut self, other: &PolyVec<DIM>) {
        self.v
            .iter_mut()
            .zip(other.v.iter())
            .for_each(|(a, b)| a.sub_assign(b));
    }

    pub fn ntt(&mut self) {
        self.v.iter_mut().for_each(|p| p.ntt());
    }

    pub fn intt(&mut self) {
        self.v.iter_mut().for_each(|p| p.intt());
    }

    /// Sum_i (a[i] (*) b[i]) where (*) is NTT-domain pointwise mul.
    #[allow(dead_code)]
    pub fn pointwise_acc(a: &PolyVec<DIM>, b: &PolyVec<DIM>) -> Poly {
        a.v.iter()
            .zip(b.v.iter())
            .fold(Poly::default(), |mut acc, (pa, pb)| {
                let t = Poly::pointwise_mul(pa, pb);
                acc.add_assign(&t);
                acc
            })
    }
}

/// Matrix type used by expand_a / mat-vec mul.
#[derive(Clone, Copy)]
pub struct PolyMat<const K: usize, const L: usize> {
    pub m: [[Poly; L]; K],
}

impl<const K: usize, const L: usize> Default for PolyMat<K, L> {
    fn default() -> Self {
        Self { m: core::array::from_fn(|_| core::array::from_fn(|_| Poly::default())) }
    }
}

impl<const K: usize, const L: usize> fmt::Debug for PolyMat<K, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolyMat")
            .field("K", &K)
            .field("L", &L)
            .finish()
    }
}
