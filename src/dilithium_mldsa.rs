// src/dilithium_mldsa.rs
//! ML-DSA-44 reference (ml-dsa crate, rc.3)

use ml_dsa::{
    signature::{Signer, Verifier},
    KeyGen, MlDsa44, Signature, SigningKey, VerifyingKey,
};

use rand_core::{CryptoRng, RngCore};

struct OsRngCompat;

impl RngCore for OsRngCompat {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).expect("getrandom failed");
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).expect("getrandom failed");
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }
}
impl CryptoRng for OsRngCompat {}

pub fn keygen_44() -> (VerifyingKey<MlDsa44>, SigningKey<MlDsa44>) {
    let mut rng = OsRngCompat;
    let kp = MlDsa44::key_gen(&mut rng);
    (kp.verifying_key().clone(), kp.signing_key().clone())
}

pub fn sign_44(sk: &SigningKey<MlDsa44>, msg: &[u8]) -> Signature<MlDsa44> {
    sk.try_sign(msg).expect("ml-dsa sign failed")
}

pub fn verify_44(vk: &VerifyingKey<MlDsa44>, msg: &[u8], sig: &Signature<MlDsa44>) -> bool {
    vk.verify(msg, sig).is_ok()
}
