// Checks official Kyber512 KAT file (PQCkemKAT_1632.rsp) against YOUR implementation,
// by reproducing the NIST KAT RNG (AES-CTR DRBG) and feeding the same randomness.

use std::fs;

use proiect::nist_drbg::NistDrbg;
use proiect::kyber_kem::{crypto_kem_enc_deterministic, crypto_kem_keypair_deterministic, crypto_kem_dec};
use proiect::kyber_params::{CIPHERTEXTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES, SYMBYTES};

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len() % 2 == 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let path = "kat/PQCkemKAT_1632.rsp";
    let txt = fs::read_to_string(path).expect("missing kat/PQCkemKAT_1632.rsp");

    let mut count: Option<u32> = None;
    let mut seed: Option<[u8; 48]> = None;
    let mut pk: Option<[u8; PUBLICKEYBYTES]> = None;
    let mut sk: Option<[u8; SECRETKEYBYTES]> = None;
    let mut ct: Option<[u8; CIPHERTEXTBYTES]> = None;
    let mut ss: Option<[u8; SYMBYTES]> = None;

    let mut ok = 0usize;

    for line in txt.lines() {
        let line = line.trim();

        if line.is_empty() {
            if let (Some(_c), Some(seed48), Some(pk_exp), Some(sk_exp), Some(ct_exp), Some(ss_exp)) =
                (count, seed, pk, sk, ct, ss)
            {
                // 1) init DRBG from official seed
                let mut drbg = NistDrbg::new(&seed48);

                // 2) reproduce Kyber ref call order:
                //    - keypair: randombytes(d,32), randombytes(z,32)
                //    - encaps:  randombytes(seed_m_raw,32)
                let mut d = [0u8; SYMBYTES];
                let mut z = [0u8; SYMBYTES];
                let mut seed_m_raw = [0u8; SYMBYTES];

                drbg.randombytes(&mut d);
                drbg.randombytes(&mut z);
                drbg.randombytes(&mut seed_m_raw);

                // 3) run YOUR Kyber with same randomness
                let (pk_got, sk_got) = crypto_kem_keypair_deterministic(&d, &z);
                assert_eq!(pk_got, pk_exp, "pk mismatch at count={:?}", count);
                assert_eq!(sk_got, sk_exp, "sk mismatch at count={:?}", count);

                let (ct_got, ss_got) = crypto_kem_enc_deterministic(&pk_got, &seed_m_raw);
                assert_eq!(ct_got, ct_exp, "ct mismatch at count={:?}", count);
                assert_eq!(ss_got, ss_exp, "ss(encaps) mismatch at count={:?}", count);

                let ss2 = crypto_kem_dec(&sk_got, &ct_got);
                assert_eq!(ss2, ss_exp, "ss(decaps) mismatch at count={:?}", count);

                ok += 1;
            }

            // reset
            count = None;
            seed = None;
            pk = None;
            sk = None;
            ct = None;
            ss = None;
            continue;
        }

        if let Some(v) = line.strip_prefix("count = ") {
            count = Some(v.parse().unwrap());
        } else if let Some(v) = line.strip_prefix("seed = ") {
            let b = unhex(v);
            let seed48_arr: [u8; 48] = b.try_into().expect("seed must be 48 bytes");
            seed = Some(seed48_arr);
        } else if let Some(v) = line.strip_prefix("pk = ") {
            let b = unhex(v);
            pk = Some(b.try_into().unwrap());
        } else if let Some(v) = line.strip_prefix("sk = ") {
            let b = unhex(v);
            sk = Some(b.try_into().unwrap());
        } else if let Some(v) = line.strip_prefix("ct = ") {
            let b = unhex(v);
            ct = Some(b.try_into().unwrap());
        } else if let Some(v) = line.strip_prefix("ss = ") {
            let b = unhex(v);
            ss = Some(b.try_into().unwrap());
        }
    }

    println!("Official KAT check OK for {} testcases", ok);
}
