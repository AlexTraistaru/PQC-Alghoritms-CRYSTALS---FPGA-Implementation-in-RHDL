// Generates deterministic KAT-like vectors for YOUR Kyber implementation.
// Output: kat_kyber512.txt (hex)

use std::fs::File;
use std::io::Write;

use proiect::kyber_kem;
use proiect::kyber_params::{CIPHERTEXTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES, SYMBYTES};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{:02x}", b)); }
    s
}

fn main() {
    let mut f = File::create("kat_kyber512.txt").expect("create output");

    // Generate N vectors
    let n = 20usize;

    for i in 0..n {
        let mut seed_kp = [0u8; SYMBYTES];
        let mut seed_m  = [0u8; SYMBYTES];
        seed_kp[0] = i as u8;
        seed_m[0]  = (i as u8) ^ 0xA5;

        let (pk, sk) = kyber_kem::kem_keypair(&seed_kp);
        let (ct, ss1) = kyber_kem::kem_encaps(&seed_m, &pk);
        let ss2 = kyber_kem::kem_decaps(&ct, &sk);

        assert_eq!(ss1, ss2, "internal KEM mismatch at i={}", i);

        writeln!(f, "count = {}", i).unwrap();
        writeln!(f, "seed_kp = {}", hex(&seed_kp)).unwrap();
        writeln!(f, "seed_m  = {}", hex(&seed_m)).unwrap();
        writeln!(f, "pk = {}", hex(&pk)).unwrap();
        writeln!(f, "sk = {}", hex(&sk)).unwrap();
        writeln!(f, "ct = {}", hex(&ct)).unwrap();
        writeln!(f, "ss = {}", hex(&ss1)).unwrap();
        writeln!(f).unwrap();

        // sanity sizes
        let _ : [u8; PUBLICKEYBYTES] = pk;
        let _ : [u8; SECRETKEYBYTES] = sk;
        let _ : [u8; CIPHERTEXTBYTES] = ct;
    }

    println!("Wrote kat_kyber512.txt ({} vectors)", n);
}
