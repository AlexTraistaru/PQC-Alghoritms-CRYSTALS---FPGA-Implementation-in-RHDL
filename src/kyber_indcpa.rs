// Kyber.CPAPKE (IND-CPA PKE) for Kyber512.
// uses kyber_sampling_rhdl FSM (via kyber_sampling.rs)
// and kyber_ntt FSM (via kyber_poly.rs).

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::kyber_codec::{ct_decode, ct_encode, pk_decode, pk_encode, poly_frommsg, poly_tomsg, polyvec_decode12, polyvec_encode12};
use crate::kyber_params::{CIPHERTEXTBYTES, INDCPA_SECRETKEYBYTES, K, POLYVECBYTES, PUBLICKEYBYTES, SYMBYTES, ETA1, ETA2};
use crate::kyber_poly::{poly_invntt, poly_ntt, poly_reduce, polyvec_ntt, polyvec_pointwise_acc, Poly, PolyVec};
use crate::kyber_sampling::gen_matrix;
use crate::kyber_sampling::poly_getnoise;
use crate::shake::{sha3_256, sha3_512};

#[inline(always)]
fn zero_poly() -> Poly {
    [rhdl::prelude::signed::<rhdl::prelude::U16>(0); crate::kyber_params::N]
}

/// Deterministic CPAPKE keypair from seed d (32 bytes): returns (pk, sk_indcpa)
pub fn indcpa_keypair_deterministic(
    d: &[u8; SYMBYTES],
) -> ([u8; PUBLICKEYBYTES], [u8; INDCPA_SECRETKEYBYTES]) {
    // (rho || sigma) = G(d) where G = SHA3-512
    let g = sha3_512(d);
    let mut rho = [0u8; SYMBYTES];
    let mut sigma = [0u8; SYMBYTES];
    rho.copy_from_slice(&g[..SYMBYTES]);
    sigma.copy_from_slice(&g[SYMBYTES..]);

    // Generate A_hat (NTT domain)
    let A_hat = gen_matrix(&rho, false);

    // Sample s and e (standard domain), then NTT
    let mut s: PolyVec = [zero_poly(); K];
    let mut e: PolyVec = [zero_poly(); K];
    let mut n: u8 = 0;

    for i in 0..K {
        s[i] = poly_getnoise(&sigma, n, ETA1);
        n = n.wrapping_add(1);
    }
    for i in 0..K {
        e[i] = poly_getnoise(&sigma, n, ETA1);
        n = n.wrapping_add(1);
    }

    polyvec_ntt(&mut s);
    polyvec_ntt(&mut e);

    // t_hat = A_hat * s_hat + e_hat
    let mut t: PolyVec = [zero_poly(); K];
    for i in 0..K {
        // dot product of row i with s
        let row: PolyVec = A_hat[i];
        let mut acc = zero_poly();
        polyvec_pointwise_acc(&mut acc, &row, &s);

        // add noise
        for j in 0..crate::kyber_params::N {
            acc[j] = acc[j] + e[i][j];
        }
        poly_reduce(&mut acc);
        t[i] = acc;
    }

    let pk = pk_encode(&t, &rho);
    let sk = polyvec_encode12(&s);
    (pk, sk)
}

/// CPAPKE encryption: ct = Enc(pk, m, coins)
pub fn indcpa_enc(
    pk: &[u8; PUBLICKEYBYTES],
    m: &[u8; SYMBYTES],
    coins: &[u8; SYMBYTES],
) -> [u8; CIPHERTEXTBYTES] {
    let (t_hat, rho) = pk_decode(pk);

    // A_hat^T
    let A_hat_t = gen_matrix(&rho, true);

    // Sample r, e1, e2 in standard domain
    let mut n: u8 = 0;
    let mut r: PolyVec = [zero_poly(); K];
    let mut e1: PolyVec = [zero_poly(); K];

    for i in 0..K {
        r[i] = poly_getnoise(coins, n, ETA1);
        n = n.wrapping_add(1);
    }
    for i in 0..K {
        e1[i] = poly_getnoise(coins, n, ETA2);
        n = n.wrapping_add(1);
    }
    let e2: Poly = poly_getnoise(coins, n, ETA2);

    // NTT(r)
    polyvec_ntt(&mut r);

    // u = InvNTT(A_hat^T * r) + e1
    let mut u: PolyVec = [zero_poly(); K];
    for i in 0..K {
        let row: PolyVec = A_hat_t[i];
        let mut acc = zero_poly();
        polyvec_pointwise_acc(&mut acc, &row, &r);
        poly_invntt(&mut acc);

        for j in 0..crate::kyber_params::N {
            acc[j] = acc[j] + e1[i][j];
        }
        u[i] = acc;
    }

    // v = InvNTT(t_hat^T * r) + e2 + m_poly
    let mut v = zero_poly();
    polyvec_pointwise_acc(&mut v, &t_hat, &r);
    poly_invntt(&mut v);

    for j in 0..crate::kyber_params::N {
        v[j] = v[j] + e2[j];
    }
    let mpoly = poly_frommsg(m);
    for j in 0..crate::kyber_params::N {
        v[j] = v[j] + mpoly[j];
    }

    ct_encode(&u, &v)
}

/// CPAPKE decryption: m = Dec(sk, ct)
pub fn indcpa_dec(
    sk: &[u8; INDCPA_SECRETKEYBYTES],
    ct: &[u8; CIPHERTEXTBYTES],
) -> [u8; SYMBYTES] {
    let (u, v) = ct_decode(ct);

    // Decode s_hat
    let mut skbytes = [0u8; POLYVECBYTES];
    skbytes.copy_from_slice(sk);
    let s_hat = polyvec_decode12(&skbytes);

    // NTT(u)
    let mut u_hat = u;
    for i in 0..K {
        poly_ntt(&mut u_hat[i]);
    }

    // mp = InvNTT( s_hat^T * u_hat )
    let mut mp = zero_poly();
    polyvec_pointwise_acc(&mut mp, &s_hat, &u_hat);
    poly_invntt(&mut mp);

    // v - mp
    let mut w = v;
    for j in 0..crate::kyber_params::N {
        w[j] = w[j] - mp[j];
    }

    poly_tomsg(&w)
}

/// Convenience: hash public key (Kyber uses H=SHA3-256)
pub fn hash_pk(pk: &[u8; PUBLICKEYBYTES]) -> [u8; SYMBYTES] {
    sha3_256(pk)
}
