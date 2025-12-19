use crate::kyber_indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair};
use crate::kyber_params::*;
use crate::shake::{sha3_256, sha3_512, shake256};

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for i in 0..a.len() { diff |= a[i] ^ b[i]; }
    diff == 0
}

/// Kyber KEM keypair: determinist din seed (32 bytes) ca să poți verifica în teste/hardware.
/// În hardware, seed-ul vine din TRNG/CSRNG.
pub fn kem_keypair(seed: &[u8; SYMBYTES]) -> ([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]) {
    let (pk, sk_indcpa) = indcpa_keypair(seed);

    let mut sk = [0u8; SECRETKEYBYTES];
    // sk = sk_indcpa || pk || H(pk) || z
    sk[..INDCPA_SECRETKEYBYTES].copy_from_slice(&sk_indcpa);
    sk[INDCPA_SECRETKEYBYTES..INDCPA_SECRETKEYBYTES+PUBLICKEYBYTES].copy_from_slice(&pk);

    let hpk = sha3_256(&pk);
    sk[INDCPA_SECRETKEYBYTES+PUBLICKEYBYTES..INDCPA_SECRETKEYBYTES+PUBLICKEYBYTES+SYMBYTES].copy_from_slice(&hpk);

    // z = sha3_256(seed||0xFF) (determinist)
    let mut z_in = [0u8; 33];
    z_in[..32].copy_from_slice(seed);
    z_in[32] = 0xFF;
    let z = sha3_256(&z_in);
    sk[SECRETKEYBYTES - SYMBYTES..].copy_from_slice(&z);

    (pk, sk)
}

/// Encaps determinist din seed_m (32 bytes) pentru verificare.
pub fn kem_encaps(seed_m: &[u8; SYMBYTES], pk: &[u8; PUBLICKEYBYTES]) -> ([u8; CIPHERTEXTBYTES], [u8; SYMBYTES]) {
    // m = H(seed_m)
    let m = sha3_256(seed_m);

    let hpk = sha3_256(pk);

    // kr = G(m || hpk) = sha3_512
    let mut inb = [0u8; 64];
    inb[..32].copy_from_slice(&m);
    inb[32..].copy_from_slice(&hpk);
    let kr = sha3_512(&inb);

    let mut kbar = [0u8; 32];
    let mut coins = [0u8; 32];
    kbar.copy_from_slice(&kr[..32]);
    coins.copy_from_slice(&kr[32..]);

    let mut ct = [0u8; CIPHERTEXTBYTES];
    indcpa_enc(&mut ct, &m, pk, &coins);

    let hct = sha3_256(&ct);

    // ss = KDF(kbar || hct) via SHAKE256 -> 32 bytes
    let mut kdf_in = [0u8; 64];
    kdf_in[..32].copy_from_slice(&kbar);
    kdf_in[32..].copy_from_slice(&hct);

    let mut ss = [0u8; 32];
    shake256(&kdf_in, &mut ss);

    (ct, ss)
}

pub fn kem_decaps(ct: &[u8; CIPHERTEXTBYTES], sk: &[u8; SECRETKEYBYTES]) -> [u8; SYMBYTES] {
    let mut sk_indcpa = [0u8; INDCPA_SECRETKEYBYTES];
    sk_indcpa.copy_from_slice(&sk[..INDCPA_SECRETKEYBYTES]);

    let mut pk = [0u8; PUBLICKEYBYTES];
    pk.copy_from_slice(&sk[INDCPA_SECRETKEYBYTES..INDCPA_SECRETKEYBYTES+PUBLICKEYBYTES]);

    let mut hpk = [0u8; 32];
    hpk.copy_from_slice(&sk[INDCPA_SECRETKEYBYTES+PUBLICKEYBYTES..INDCPA_SECRETKEYBYTES+PUBLICKEYBYTES+32]);

    let mut z = [0u8; 32];
    z.copy_from_slice(&sk[SECRETKEYBYTES-32..]);

    // m = indcpa_dec(ct, sk_indcpa)
    // CORECTAT: Nu mai facem hash aici. indcpa_dec returnează exact ce a primit indcpa_enc.
    let mut m = [0u8; 32];
    indcpa_dec(&mut m, ct, &sk_indcpa);
    
    // LINIA S-A ȘTERS: m = sha3_256(&m); 

    // kr = G(m || hpk)
    let mut inb = [0u8; 64];
    inb[..32].copy_from_slice(&m);
    inb[32..].copy_from_slice(&hpk);
    let kr = sha3_512(&inb);

    let mut kbar = [0u8; 32];
    let mut coins = [0u8; 32];
    kbar.copy_from_slice(&kr[..32]);
    coins.copy_from_slice(&kr[32..]);

    // cmp = indcpa_enc(m, pk, coins)
    let mut cmp = [0u8; CIPHERTEXTBYTES];
    indcpa_enc(&mut cmp, &m, &pk, &coins);

    let hct = sha3_256(ct);

    // if ct==cmp use kbar else use z
    let use_k = if ct_eq(ct, &cmp) { kbar } else { z };

    let mut kdf_in = [0u8; 64];
    kdf_in[..32].copy_from_slice(&use_k);
    kdf_in[32..].copy_from_slice(&hct);

    let mut ss = [0u8; 32];
    shake256(&kdf_in, &mut ss);
    ss
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_roundtrip() {
        let seed = [7u8; 32];
        let (pk, sk) = kem_keypair(&seed);

        let mseed = [9u8; 32];
        let (ct, ss1) = kem_encaps(&mseed, &pk);
        let ss2 = kem_decaps(&ct, &sk);

        assert_eq!(ss1, ss2);
    }
}

