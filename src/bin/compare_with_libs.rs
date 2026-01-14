// Compares:
//  1) Kyber512 interoperability (your impl <-> pqcrypto-kyber)
//     - Includes a DIAGNOSTIC mode using library-generated keys to localize mismatches.
//  2) Dilithium: your sign/verify vs ML-DSA-44 reference (ml-dsa crate)
//     - Not byte-level interop (types differ), but correctness + timing comparison.
// - Kyber interop checks compare SHARED SECRET only (the correct interop criterion).
// - If Kyber DIAGNOSTIC fails with lib keys, mismatch is in INDCPA/pack/unpack/hash conventions.
// - If DIAGNOSTIC passes but your keypair interop fails, mismatch is in your keypair encoding/layout.

use std::time::Instant;

use proiect::kyber_kem;
use proiect::kyber_params::{CIPHERTEXTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES, SYMBYTES};

use proiect::dilithium;
use proiect::dilithium_mldsa;

// pqcrypto Kyber512 (PQClean bindings)
use pqcrypto_kyber::kyber512 as pqk;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

fn arr32(x: u8) -> [u8; 32] {
    [x; 32]
}

fn hex32(label: &str, x: &[u8; 32]) {
    print!("{label}: ");
    for b in x {
        print!("{:02x}", b);
    }
    println!();
}

fn main() {
    // ============================================================
    // KYBER512: DIAGNOSTIC using library-generated keys
    // ============================================================
    println!("=== Kyber512: DIAGNOSTIC (library keys) ===");

    // Library keypair
    let (pk_lib, sk_lib) = pqk::keypair();

    // Convert to raw bytes so we can feed into your implementation
    let pk_lib_bytes: [u8; PUBLICKEYBYTES] = pk_lib.as_bytes().try_into().unwrap();
    let sk_lib_bytes: [u8; SECRETKEYBYTES] = sk_lib.as_bytes().try_into().unwrap();

    // (1) YOUR encaps -> LIB decaps
    {
        let seed_m = arr32(0x42);
        let (ct_hw, ss_hw) = kyber_kem::kem_encaps(&seed_m, &pk_lib_bytes);

        let ct_as_lib = pqk::Ciphertext::from_bytes(&ct_hw).expect("ct bytes invalid for pqcrypto");
        let ss_lib = pqk::decapsulate(&ct_as_lib, &sk_lib);
        let ss_lib_arr: [u8; SYMBYTES] = ss_lib.as_bytes().try_into().unwrap();

        if ss_hw == ss_lib_arr {
            println!("OK: your encaps -> lib decaps");
        } else {
            println!("FAIL: your encaps -> lib decaps (shared secret mismatch)");
            hex32("  ss_hw ", &ss_hw);
            hex32("  ss_lib", &ss_lib_arr);
            // If you want hard fail here, uncomment:
            // panic!("Stop: encaps mismatch");
        }
    }

    // (2) LIB encaps -> YOUR decaps
    {
        let (ss_lib, ct_lib) = pqk::encapsulate(&pk_lib);
        let ct_lib_bytes: [u8; CIPHERTEXTBYTES] = ct_lib.as_bytes().try_into().unwrap();
        let ss_hw = kyber_kem::kem_decaps(&ct_lib_bytes, &sk_lib_bytes);

        let ss_lib_arr: [u8; SYMBYTES] = ss_lib.as_bytes().try_into().unwrap();

        if ss_hw == ss_lib_arr {
            println!("OK: lib encaps -> your decaps");
        } else {
            println!("FAIL: lib encaps -> your decaps (shared secret mismatch)");
            hex32("  ss_hw ", &ss_hw);
            hex32("  ss_lib", &ss_lib_arr);
            // If you want hard fail here, uncomment:
            // panic!("Stop: decaps mismatch");
        }
    }

    // ============================================================
    // KYBER512: Interop tests using YOUR keys
    // ============================================================
    println!("\n=== Kyber512: interop (lib <-> implementarea ta, using YOUR keys) ===");

    // ------------------------------------------------------------
    // (A) Library encapsulate -> YOUR decapsulate (using YOUR keypair)
    // ------------------------------------------------------------
    {
        let seed_kp = arr32(0x11);
        let (pk_hw, sk_hw) = kyber_kem::kem_keypair(&seed_kp);

        let pk_as_lib = pqk::PublicKey::from_bytes(&pk_hw).expect("pk bytes invalid for pqcrypto");
        let (ss_lib, ct_lib) = pqk::encapsulate(&pk_as_lib);

        let ct_hw: [u8; CIPHERTEXTBYTES] = ct_lib.as_bytes().try_into().unwrap();
        let ss_hw = kyber_kem::kem_decaps(&ct_hw, &sk_hw);

        let ss_lib_arr: [u8; SYMBYTES] = ss_lib.as_bytes().try_into().unwrap();

        if ss_hw == ss_lib_arr {
            println!("OK: lib encaps -> hw decaps (shared secret match)");
        } else {
            println!("FAIL: lib encaps -> hw decaps (shared secret mismatch)");
            hex32("  ss_hw ", &ss_hw);
            hex32("  ss_lib", &ss_lib_arr);
        }
    }

    // ------------------------------------------------------------
    // (B) YOUR encapsulate -> Library decapsulate (using LIB keypair)
    // ------------------------------------------------------------
    {
        let (pk2_lib, sk2_lib) = pqk::keypair();
        let pk2_hw: [u8; PUBLICKEYBYTES] = pk2_lib.as_bytes().try_into().unwrap();
        let sk2_hw: [u8; SECRETKEYBYTES] = sk2_lib.as_bytes().try_into().unwrap();

        let seed_m = arr32(0x22);
        let (ct_hw, ss_hw) = kyber_kem::kem_encaps(&seed_m, &pk2_hw);

        let ct2_lib = pqk::Ciphertext::from_bytes(&ct_hw).expect("ct bytes invalid for pqcrypto");
        let sk2_lib2 = pqk::SecretKey::from_bytes(&sk2_hw).expect("sk bytes invalid for pqcrypto");
        let ss2_lib = pqk::decapsulate(&ct2_lib, &sk2_lib2);
        let ss2_lib_arr: [u8; SYMBYTES] = ss2_lib.as_bytes().try_into().unwrap();

        if ss_hw == ss2_lib_arr {
            println!("OK: hw encaps -> lib decaps (shared secret match)");
        } else {
            println!("FAIL: hw encaps -> lib decaps (shared secret mismatch)");
            hex32("  ss_hw ", &ss_hw);
            hex32("  ss_lib", &ss2_lib_arr);
        }
    }

    // ------------------------------------------------------------
    // Timing (software wall-clock) for pqcrypto Kyber512
    // ------------------------------------------------------------
    println!("\n=== Kyber512: pqcrypto timing (CPU reference) ===");
    let iters = 200;

    let t0 = Instant::now();
    for _ in 0..iters {
        let (_pk, _sk) = pqk::keypair();
    }
    println!("pqcrypto keypair avg: {:?}/op", t0.elapsed() / iters);

    let (pk, sk) = pqk::keypair();

    let t1 = Instant::now();
    for _ in 0..iters {
        let (_ss, _ct) = pqk::encapsulate(&pk);
    }
    println!("pqcrypto encaps avg: {:?}/op", t1.elapsed() / iters);

    let (_ss, ct) = pqk::encapsulate(&pk);

    let t2 = Instant::now();
    for _ in 0..iters {
        let _ss2 = pqk::decapsulate(&ct, &sk);
    }
    println!("pqcrypto decaps avg: {:?}/op", t2.elapsed() / iters);

    // ============================================================
    // DILITHIUM: your impl vs ML-DSA-44 reference (no byte interop)
    // ============================================================
    println!("\n=== Dilithium2: comparatie (a ta) vs referinta ML-DSA-44 (ml-dsa) ===");
    let msg = b"test message for evaluation";

    // (1) Your Dilithium
    {
        let (pk_my, sk_my) = dilithium::keygen(arr32(0x33));
        let sig_my = dilithium::sign(&sk_my, msg);

        assert!(dilithium::verify(&pk_my, msg, &sig_my));
        assert!(!dilithium::verify(&pk_my, b"tampered", &sig_my));
        println!("OK: dilithium (ta) sign/verify functional");

        let iters2 = 200;

        let t3 = Instant::now();
        for _ in 0..iters2 {
            let (_pk, _sk) = dilithium::keygen(arr32(0x44));
        }
        println!("dilithium (ta) keygen avg: {:?}/op", t3.elapsed() / iters2);

        let (_pk, sk) = dilithium::keygen(arr32(0x55));
        let t4 = Instant::now();
        for _ in 0..iters2 {
            let _sig = dilithium::sign(&sk, msg);
        }
        println!("dilithium (ta) sign avg:   {:?}/op", t4.elapsed() / iters2);

        let (pk, sk) = dilithium::keygen(arr32(0x66));
        let sig = dilithium::sign(&sk, msg);
        let t5 = Instant::now();
        for _ in 0..iters2 {
            let _ok = dilithium::verify(&pk, msg, &sig);
        }
        println!("dilithium (ta) verify avg: {:?}/op", t5.elapsed() / iters2);
    }

    // (2) Reference ML-DSA-44 (ml-dsa crate via dilithium_mldsa.rs)
    {
        let (vk_ref, sk_ref) = dilithium_mldsa::keygen_44();
        let sig_ref = dilithium_mldsa::sign_44(&sk_ref, msg);

        assert!(dilithium_mldsa::verify_44(&vk_ref, msg, &sig_ref));
        assert!(!dilithium_mldsa::verify_44(&vk_ref, b"tampered", &sig_ref));
        println!("OK: ml-dsa44 sign/verify functional");

        let iters3 = 200;

        let t6 = Instant::now();
        for _ in 0..iters3 {
            let (_vk, _sk) = dilithium_mldsa::keygen_44();
        }
        println!("ml-dsa44 keygen avg: {:?}/op", t6.elapsed() / iters3);

        let (_vk, sk) = dilithium_mldsa::keygen_44();
        let t7 = Instant::now();
        for _ in 0..iters3 {
            let _sig = dilithium_mldsa::sign_44(&sk, msg);
        }
        println!("ml-dsa44 sign avg:   {:?}/op", t7.elapsed() / iters3);

        let (vk, sk) = dilithium_mldsa::keygen_44();
        let sig = dilithium_mldsa::sign_44(&sk, msg);
        let t8 = Instant::now();
        for _ in 0..iters3 {
            let _ok = dilithium_mldsa::verify_44(&vk, msg, &sig);
        }
        println!("ml-dsa44 verify avg: {:?}/op", t8.elapsed() / iters3);
    }

    println!("\nDONE.");
}
