// Kyber CCA-secure KEM (Kyber512), Fujisaki-Okamoto transform.
// RHDL-heavy INDCPA underneath (sampling + NTT are FSM-style).

#![allow(dead_code)]

use crate::kyber_indcpa::{hash_pk, indcpa_dec, indcpa_enc, indcpa_keypair_deterministic};
use crate::kyber_params::{CIPHERTEXTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES, SYMBYTES, INDCPA_SECRETKEYBYTES};
use crate::shake::{sha3_256, sha3_512, shake256};

#[inline(always)]
fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[inline(always)]
fn cmov(dest: &mut [u8], src: &[u8], move_if: bool) {
    let mask: u8 = if move_if { 0xFF } else { 0x00 };
    for i in 0..dest.len() {
        dest[i] = (dest[i] & !mask) | (src[i] & mask);
    }
}

/// Deterministic KEM keypair from (d,z) seeds (both 32 bytes).
pub fn crypto_kem_keypair_deterministic(
    d: &[u8; SYMBYTES],
    z: &[u8; SYMBYTES],
) -> ([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]) {
    let (pk, sk_indcpa) = indcpa_keypair_deterministic(d);
    let hpk = hash_pk(&pk);

    // sk = sk_indcpa || pk || H(pk) || z
    let mut sk = [0u8; SECRETKEYBYTES];
    let mut off = 0usize;

    sk[off..off + INDCPA_SECRETKEYBYTES].copy_from_slice(&sk_indcpa);
    off += INDCPA_SECRETKEYBYTES;

    sk[off..off + PUBLICKEYBYTES].copy_from_slice(&pk);
    off += PUBLICKEYBYTES;

    sk[off..off + SYMBYTES].copy_from_slice(&hpk);
    off += SYMBYTES;

    sk[off..off + SYMBYTES].copy_from_slice(z);

    (pk, sk)
}

/// Deterministic encaps using seed_m as entropy.
/// Returns (ct, ss).
pub fn crypto_kem_enc_deterministic(
    pk: &[u8; PUBLICKEYBYTES],
    seed_m: &[u8; SYMBYTES],
) -> ([u8; CIPHERTEXTBYTES], [u8; SYMBYTES]) {
    // m = H(seed_m)
    let m = sha3_256(seed_m);
    let hpk = hash_pk(pk);

    // (Kbar || r) = G(m || H(pk)) where G=SHA3-512
    let mut buf = [0u8; 2 * SYMBYTES];
    buf[..SYMBYTES].copy_from_slice(&m);
    buf[SYMBYTES..].copy_from_slice(&hpk);

    let gr = sha3_512(&buf);
    let mut kbar = [0u8; SYMBYTES];
    let mut coins = [0u8; SYMBYTES];
    kbar.copy_from_slice(&gr[..SYMBYTES]);
    coins.copy_from_slice(&gr[SYMBYTES..]);

    // c = Enc(pk, m, coins)
    let ct = indcpa_enc(pk, &m, &coins);

    // ss = KDF(Kbar || H(c)) where KDF=SHAKE256 to 32 bytes
    let hc = sha3_256(&ct);
    let mut kd_in = [0u8; 2 * SYMBYTES];
    kd_in[..SYMBYTES].copy_from_slice(&kbar);
    kd_in[SYMBYTES..].copy_from_slice(&hc);

    let mut ss = [0u8; SYMBYTES];
    shake256(&kd_in, &mut ss);

    (ct, ss)
}

/// KEM decapsulation: returns shared secret ss.
pub fn crypto_kem_dec(sk: &[u8; SECRETKEYBYTES], ct: &[u8; CIPHERTEXTBYTES]) -> [u8; SYMBYTES] {
    // Layout: sk_indcpa || pk || H(pk) || z
    let sk_indcpa_len = INDCPA_SECRETKEYBYTES;
    let pk_off = sk_indcpa_len;
    let hpk_off = pk_off + PUBLICKEYBYTES;
    let z_off = hpk_off + SYMBYTES;

    let mut pk = [0u8; PUBLICKEYBYTES];
    pk.copy_from_slice(&sk[pk_off..pk_off + PUBLICKEYBYTES]);

    let mut hpk = [0u8; SYMBYTES];
    hpk.copy_from_slice(&sk[hpk_off..hpk_off + SYMBYTES]);

    let mut z = [0u8; SYMBYTES];
    z.copy_from_slice(&sk[z_off..z_off + SYMBYTES]);

    // m' = Dec(sk_indcpa, c)
    let mut sk_indcpa = [0u8; INDCPA_SECRETKEYBYTES];
    sk_indcpa.copy_from_slice(&sk[..sk_indcpa_len]);

    let mprime = indcpa_dec(&sk_indcpa, ct);

    // (Kbar' || r') = G(m' || H(pk))
    let mut buf = [0u8; 2 * SYMBYTES];
    buf[..SYMBYTES].copy_from_slice(&mprime);
    buf[SYMBYTES..].copy_from_slice(&hpk);

    let gr = sha3_512(&buf);
    let mut kbar = [0u8; SYMBYTES];
    let mut coins = [0u8; SYMBYTES];
    kbar.copy_from_slice(&gr[..SYMBYTES]);
    coins.copy_from_slice(&gr[SYMBYTES..]);

    // c' = Enc(pk, m', r')
    let ct_prime = indcpa_enc(&pk, &mprime, &coins);

    // If c != c' then Kbar = z (constant-time)
    let ok = ct_equal(ct, &ct_prime);
    cmov(&mut kbar, &z, !ok);

    // ss = KDF(Kbar || H(c))
    let hc = sha3_256(ct);
    let mut kd_in = [0u8; 2 * SYMBYTES];
    kd_in[..SYMBYTES].copy_from_slice(&kbar);
    kd_in[SYMBYTES..].copy_from_slice(&hc);

    let mut ss = [0u8; SYMBYTES];
    shake256(&kd_in, &mut ss);
    ss
}

// -----------------------------------------------------------------------------
// Simple wrappers used by your demo (kyber_demo.rs)
// -----------------------------------------------------------------------------

/// Demo-friendly deterministic keypair from a single 32-byte seed.
pub fn kem_keypair(seed: &[u8; SYMBYTES]) -> ([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]) {
    // Derive (d,z) from SHA3-512(seed)
    let g = sha3_512(seed);
    let mut d = [0u8; SYMBYTES];
    let mut z = [0u8; SYMBYTES];
    d.copy_from_slice(&g[..SYMBYTES]);
    z.copy_from_slice(&g[SYMBYTES..]);
    crypto_kem_keypair_deterministic(&d, &z)
}

/// Demo-friendly deterministic encaps from a 32-byte seed.
pub fn kem_encaps(seed_m: &[u8; SYMBYTES], pk: &[u8; PUBLICKEYBYTES]) -> ([u8; CIPHERTEXTBYTES], [u8; SYMBYTES]) {
    crypto_kem_enc_deterministic(pk, seed_m)
}

/// Demo-friendly decaps.
pub fn kem_decaps(ct: &[u8; CIPHERTEXTBYTES], sk: &[u8; SECRETKEYBYTES]) -> [u8; SYMBYTES] {
    crypto_kem_dec(sk, ct)
}
