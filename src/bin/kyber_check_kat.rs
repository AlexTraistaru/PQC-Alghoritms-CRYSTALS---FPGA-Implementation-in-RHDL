// Checks kat_kyber512.txt produced by kyber_gen_kat.rs.

use std::fs;

use proiect::kyber_kem;
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
    let txt = fs::read_to_string("kat_kyber512.txt").expect("missing kat_kyber512.txt");
    let mut ok = 0usize;

    // Explicit types (fixes E0282)
    let mut seed_kp: Option<Vec<u8>> = None;
    let mut seed_m: Option<Vec<u8>> = None;
    let mut pk: Option<Vec<u8>> = None;
    let mut sk: Option<Vec<u8>> = None;
    let mut ct: Option<Vec<u8>> = None;
    let mut ss: Option<Vec<u8>> = None;

    for line in txt.lines() {
        let line = line.trim();

        if line.is_empty() {
            // end of one test case
            if let (Some(seed_kp_v), Some(seed_m_v), Some(pk_v), Some(sk_v), Some(ct_v), Some(ss_v)) =
                (&seed_kp, &seed_m, &pk, &sk, &ct, &ss)
            {
                let seed_kp_arr: [u8; SYMBYTES] = seed_kp_v.clone().try_into().unwrap();
                let seed_m_arr: [u8; SYMBYTES] = seed_m_v.clone().try_into().unwrap();

                let pk_arr: [u8; PUBLICKEYBYTES] = pk_v.clone().try_into().unwrap();
                let sk_arr: [u8; SECRETKEYBYTES] = sk_v.clone().try_into().unwrap();
                let ct_arr: [u8; CIPHERTEXTBYTES] = ct_v.clone().try_into().unwrap();
                let ss_exp: [u8; SYMBYTES] = ss_v.clone().try_into().unwrap();

                // recompute from seeds
                let (pk2, sk2) = kyber_kem::kem_keypair(&seed_kp_arr);
                assert_eq!(pk2, pk_arr, "pk mismatch");
                assert_eq!(sk2, sk_arr, "sk mismatch");

                let (ct2, ss1) = kyber_kem::kem_encaps(&seed_m_arr, &pk_arr);
                assert_eq!(ct2, ct_arr, "ct mismatch");
                assert_eq!(ss1, ss_exp, "ss(encaps) mismatch");

                let ss2 = kyber_kem::kem_decaps(&ct_arr, &sk_arr);
                assert_eq!(ss2, ss_exp, "ss(decaps) mismatch");

                ok += 1;
            }

            // reset for next case
            seed_kp = None;
            seed_m = None;
            pk = None;
            sk = None;
            ct = None;
            ss = None;
            continue;
        }

        if let Some(v) = line.strip_prefix("seed_kp = ") {
            seed_kp = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("seed_m  = ") {
            seed_m = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("pk = ") {
            pk = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("sk = ") {
            sk = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("ct = ") {
            ct = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("ss = ") {
            ss = Some(unhex(v));
        }
    }

    println!("KAT check OK for {} vectors", ok);
}
