use crate::shake::shake256;
use crate::dilithium_params::{Dilithium2, N, Q, K, L, D, GAMMA1, GAMMA2, BETA, OMEGA, PK_BYTES, POLYW1_PACKEDBYTES};
use crate::dilithium_poly::{Poly, PolyVec};
use crate::dilithium_rounding::{power2round, high_bits, low_bits, make_hint, use_hint, norm_bound};
use crate::dilithium_sample::{expand_a, expand_s, expand_mask, challenge, mat_vec_mul_ntt};
use crate::dilithium_pack::{
    pack_poly_t1, polyvec_w1_bytes, poly_check_norm,
};

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub rho: [u8; 32],
    pub t1: PolyVec<K>,
}

#[derive(Clone, Debug)]
pub struct SecretKey {
    pub rho: [u8; 32],
    pub key: [u8; 32],
    pub tr: [u8; 64],
    pub s1: PolyVec<L>,
    pub s2: PolyVec<K>,
    pub t0: PolyVec<K>,
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub c_tilde: [u8; 32],
    pub z: PolyVec<L>,
    pub h: PolyVec<K>,
}

// Helper to center coefficients in [-Q/2, Q/2]
fn normalize_poly(p: &mut Poly) {
    for c in p.coeffs.iter_mut() {
        let mut v = *c % Q;
        if v < 0 {
            v += Q;
        }
        if v > Q / 2 {
            v -= Q;
        }
        *c = v;
    }
}

fn hash_to_96(seed: &[u8; 32]) -> [u8; 96] {
    let mut v = vec![0u8; 96];
    shake256(seed, &mut v);
    let mut out = [0u8; 96];
    out.copy_from_slice(&v);
    out
}

pub fn keygen(seed: [u8; 32]) -> (PublicKey, SecretKey) {
    let z = hash_to_96(&seed);

    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    rho.copy_from_slice(&z[0..32]);
    rho_prime.copy_from_slice(&z[32..96]);

    let mut key_vec = vec![0u8; 32];
    shake256(&z, &mut key_vec);
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);

    let a_hat = expand_a(&rho);
    let (s1, s2) = expand_s(&rho_prime);

    // t = A*s1 + s2
    let mut s1_hat = s1;
    s1_hat.ntt();

    let mut t = PolyVec::<K>::default();
    for i in 0..K {
        let mut acc = Poly::default();
        for j in 0..L {
            let tp = Poly::pointwise_mul(&a_hat.m[i][j], &s1_hat.v[j]);
            acc.add_assign(&tp);
        }
        acc.intt();
        normalize_poly(&mut acc);
        acc.add_assign(&s2.v[i]);
        normalize_poly(&mut acc);
        t.v[i] = acc;
    }

    // power2round -> t1,t0
    let mut t1 = PolyVec::<K>::default();
    let mut t0 = PolyVec::<K>::default();
    for i in 0..K {
        for j in 0..N {
            let (a1, a0) = power2round(t.v[i].coeffs[j], D);
            t1.v[i].coeffs[j] = a1;
            t0.v[i].coeffs[j] = a0;
        }
    }

    // tr = H(rho || t1)
    let mut pk_bytes = Vec::with_capacity(PK_BYTES);
    pk_bytes.extend_from_slice(&rho);
    for i in 0..K {
        pk_bytes.extend_from_slice(&pack_poly_t1(&t1.v[i]));
    }
    
    let mut tr_vec = vec![0u8; 64];
    shake256(&pk_bytes, &mut tr_vec);
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&tr_vec);

    (
        PublicKey { rho, t1 },
        SecretKey { rho, key, tr, s1, s2, t0 },
    )
}

pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    let mut trm = Vec::with_capacity(64 + msg.len());
    trm.extend_from_slice(&sk.tr);
    trm.extend_from_slice(msg);
    
    let mut mu = vec![0u8; 64];
    shake256(&trm, &mut mu);

    let mut km = Vec::with_capacity(32 + 64);
    km.extend_from_slice(&sk.key);
    km.extend_from_slice(&mu);
    
    let mut rho_prime = vec![0u8; 64];
    shake256(&km, &mut rho_prime);

    let a_hat = expand_a(&sk.rho);

    let mut s1_hat = sk.s1;
    s1_hat.ntt();
    let mut s2_hat = sk.s2;
    s2_hat.ntt();
    let mut t0_hat = sk.t0;
    t0_hat.ntt();

    let mut kappa: u16 = 0;
    let mut attempts = 0;

    loop {
        attempts += 1;
        if attempts > 1000 {
             panic!("Sign stuck in loop");
        }

        // 1. Expand y (Standard Domain)
        let y = expand_mask(&rho_prime, kappa);
        
        // 2. Compute w = A * y
        // Funcția mat_vec_mul_ntt din dilithium_sample.rs face intern:
        // y -> NTT -> Multiply -> INTT.
        // Deci rezultatul `w` este deja în Standard Domain.
        let w = mat_vec_mul_ntt(&a_hat, &y); // Fără 'mut'
        
        // w1 = HighBits(w)
        let mut w1 = PolyVec::<K>::default();
        for i in 0..K {
            let mut wi = w.v[i];
            normalize_poly(&mut wi);
            for j in 0..N {
                w1.v[i].coeffs[j] = high_bits(wi.coeffs[j], GAMMA2);
            }
        }

        // c_tilde = H(mu || w1_bytes)
        let mut h_in = Vec::with_capacity(64 + K * POLYW1_PACKEDBYTES);
        h_in.extend_from_slice(&mu);
        h_in.extend_from_slice(&polyvec_w1_bytes::<Dilithium2, K>(&w1));
        
        let mut ctil = vec![0u8; 32];
        shake256(&h_in, &mut ctil);
        
        let mut c_tilde = [0u8; 32];
        c_tilde.copy_from_slice(&ctil);

        let c = challenge(&c_tilde);
        let mut c_hat = c;
        c_hat.ntt();

        // z = y + c*s1
        let mut z = PolyVec::<L>::default();
        for i in 0..L {
            let mut prod = Poly::pointwise_mul(&c_hat, &s1_hat.v[i]);
            prod.intt();
            
            z.v[i] = y.v[i];
            z.v[i].add_assign(&prod);
            normalize_poly(&mut z.v[i]);
        }

        // Check norm of z
        let z_bound = GAMMA1 - BETA;
        if (0..L).any(|i| !poly_check_norm(&z.v[i], z_bound)) {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        // Check norm of r0 = LowBits(w - cs2)
        let mut w_minus_cs2 = PolyVec::<K>::default();
        let mut ok = true;
        
        for i in 0..K {
            let mut prod = Poly::pointwise_mul(&c_hat, &s2_hat.v[i]);
            prod.intt();
            
            let mut t = w.v[i]; // w este Standard
            t.sub_assign(&prod); // prod este Standard (după INTT mai sus)
            normalize_poly(&mut t);
            
            w_minus_cs2.v[i] = t; 

            for j in 0..N {
                let r0 = low_bits(t.coeffs[j], GAMMA2);
                if norm_bound(r0) >= GAMMA2 - BETA {
                    ok = false;
                    break;
                }
            }
            if !ok { break; }
        }
        if !ok {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        // Hints
        let mut h = PolyVec::<K>::default();
        let mut omega_cnt = 0usize;
        for i in 0..K {
            let mut prod = Poly::pointwise_mul(&c_hat, &t0_hat.v[i]);
            prod.intt();
            
            for j in 0..N {
                let mut ct0 = prod.coeffs[j] % Q;
                if ct0 < 0 { ct0 += Q; }
                if ct0 > Q/2 { ct0 -= Q; }
                
                let val_verifier = w_minus_cs2.v[i].coeffs[j] + ct0;
                
                let hint = make_hint(-ct0, val_verifier, GAMMA2);
                
                h.v[i].coeffs[j] = hint as i32;
                if hint != 0 { omega_cnt += 1; }
            }
        }
        if omega_cnt > OMEGA {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        return Signature { c_tilde, z, h };
    }
}

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let z_bound = GAMMA1 - BETA;
    if (0..L).any(|i| !poly_check_norm(&sig.z.v[i], z_bound)) {
        return false;
    }

    let mut pk_bytes = Vec::with_capacity(PK_BYTES);
    pk_bytes.extend_from_slice(&pk.rho);
    for i in 0..K {
        pk_bytes.extend_from_slice(&pack_poly_t1(&pk.t1.v[i]));
    }
    
    let mut tr = vec![0u8; 64];
    shake256(&pk_bytes, &mut tr);

    let mut inbuf = Vec::with_capacity(64 + msg.len());
    inbuf.extend_from_slice(&tr);
    inbuf.extend_from_slice(msg);
    
    let mut mu = vec![0u8; 64];
    shake256(&inbuf, &mut mu);

    let a_hat = expand_a(&pk.rho);

    let c = challenge(&sig.c_tilde);
    let mut c_hat = c;
    c_hat.ntt();

    let mut z_hat = sig.z;
    z_hat.ntt();

    // w' = A*z - c*t1*2^d
    let mut w_prime = PolyVec::<K>::default();
    for i in 0..K {
        let mut acc = Poly::default();
        for j in 0..L {
            let tp = Poly::pointwise_mul(&a_hat.m[i][j], &z_hat.v[j]);
            acc.add_assign(&tp);
        }
        acc.intt();
        normalize_poly(&mut acc);
        w_prime.v[i] = acc;
    }

    let mut t1_shift = pk.t1;
    for i in 0..K {
        t1_shift.v[i].shiftl(D);
        t1_shift.v[i].ntt();
    }
    for i in 0..K {
        let mut prod = Poly::pointwise_mul(&c_hat, &t1_shift.v[i]);
        prod.intt();
        
        w_prime.v[i].sub_assign(&prod);
        normalize_poly(&mut w_prime.v[i]);
    }

    // w1' = UseHint(h, w')
    let mut w1_prime = PolyVec::<K>::default();
    let mut ones = 0usize;
    for i in 0..K {
        for j in 0..N {
            let hint = sig.h.v[i].coeffs[j];
            if hint != 0 { ones += 1; }
            w1_prime.v[i].coeffs[j] = use_hint(w_prime.v[i].coeffs[j], hint as u8, GAMMA2);
        }
    }
    if ones > OMEGA { return false; }

    // c_tilde' = H(mu || w1_prime_bytes)
    let mut h_in = Vec::with_capacity(64 + K * POLYW1_PACKEDBYTES);
    h_in.extend_from_slice(&mu);
    h_in.extend_from_slice(&polyvec_w1_bytes::<Dilithium2, K>(&w1_prime));
    
    let mut ctil2 = vec![0u8; 32];
    shake256(&h_in, &mut ctil2);

    ctil2.as_slice() == sig.c_tilde
}