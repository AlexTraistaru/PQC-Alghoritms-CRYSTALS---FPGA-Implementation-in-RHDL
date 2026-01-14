use std::time::{Duration, Instant};

use proiect::dilithium;
use proiect::dilithium_mldsa;

use pqcrypto_kyber::kyber512 as pqk;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _, SharedSecret as _, Ciphertext as _};

fn arr32(x: u8) -> [u8; 32] { [x; 32] }

fn avg(d: Duration, n: u32) -> Duration { d / n }

fn main() {
    let iters: u32 = 200;

    // --- Kyber software baseline (pqcrypto) ---
    println!("=== CPU baseline: pqcrypto Kyber512 ===");

    let t0 = Instant::now();
    for _ in 0..iters {
        let _ = pqk::keypair();
    }
    println!("keypair avg: {:?}", avg(t0.elapsed(), iters));

    let (pk, sk) = pqk::keypair();
    let t1 = Instant::now();
    for _ in 0..iters {
        let _ = pqk::encapsulate(&pk);
    }
    println!("encaps avg: {:?}", avg(t1.elapsed(), iters));

    let (_ss, ct) = pqk::encapsulate(&pk);
    let t2 = Instant::now();
    for _ in 0..iters {
        let _ = pqk::decapsulate(&ct, &sk);
    }
    println!("decaps avg: {:?}", avg(t2.elapsed(), iters));

    // --- Dilithium: your impl vs ML-DSA ref ---
    println!("\n=== CPU: Dilithium (ta) vs ML-DSA-44 (ref) ===");
    let msg = b"evaluation message";

    // your dilithium
    {
        let (pk_my, sk_my) = dilithium::keygen(arr32(0x11));
        let sig = dilithium::sign(&sk_my, msg);
        assert!(dilithium::verify(&pk_my, msg, &sig));
    }

    let t3 = Instant::now();
    for _ in 0..iters {
        let _ = dilithium::keygen(arr32(0x22));
    }
    println!("your keygen avg: {:?}", avg(t3.elapsed(), iters));

    let (_pk, sk) = dilithium::keygen(arr32(0x33));
    let t4 = Instant::now();
    for _ in 0..iters {
        let _ = dilithium::sign(&sk, msg);
    }
    println!("your sign avg:   {:?}", avg(t4.elapsed(), iters));

    let (pk, sk) = dilithium::keygen(arr32(0x44));
    let sig = dilithium::sign(&sk, msg);
    let t5 = Instant::now();
    for _ in 0..iters {
        let _ = dilithium::verify(&pk, msg, &sig);
    }
    println!("your verify avg: {:?}", avg(t5.elapsed(), iters));

    // ml-dsa reference
    {
        let (vk, sk) = dilithium_mldsa::keygen_44();
        let sig = dilithium_mldsa::sign_44(&sk, msg);
        assert!(dilithium_mldsa::verify_44(&vk, msg, &sig));
    }

    let t6 = Instant::now();
    for _ in 0..iters {
        let _ = dilithium_mldsa::keygen_44();
    }
    println!("ref keygen avg: {:?}", avg(t6.elapsed(), iters));

    let (_vk, sk) = dilithium_mldsa::keygen_44();
    let t7 = Instant::now();
    for _ in 0..iters {
        let _ = dilithium_mldsa::sign_44(&sk, msg);
    }
    println!("ref sign avg:   {:?}", avg(t7.elapsed(), iters));

    let (vk, sk) = dilithium_mldsa::keygen_44();
    let sig = dilithium_mldsa::sign_44(&sk, msg);
    let t8 = Instant::now();
    for _ in 0..iters {
        let _ = dilithium_mldsa::verify_44(&vk, msg, &sig);
    }
    println!("ref verify avg: {:?}", avg(t8.elapsed(), iters));
}
