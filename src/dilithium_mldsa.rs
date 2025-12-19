//! Full ML-DSA (Dilithium) via RustCrypto `ml-dsa` crate.
//! You call this as a reference implementation; later you can swap in your own HW/NTT.

use ml_dsa::{
    EncodedSignature, EncodedSigningKey, EncodedVerifyingKey,
    KeyGen, MlDsa44, Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};

pub fn keygen_44() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let kp = MlDsa44::key_gen(&mut rng);

    // Make the types explicit (avoids inference errors)
    let pk: EncodedVerifyingKey<MlDsa44> = kp.verifying_key().encode();
    let sk: EncodedSigningKey<MlDsa44> = kp.signing_key().encode();

    (pk.as_slice().to_vec(), sk.as_slice().to_vec())
}

pub fn sign_44_det(sk_bytes: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let enc_sk: EncodedSigningKey<MlDsa44> = EncodedSigningKey::<MlDsa44>::try_from(sk_bytes).ok()?;
    let sk = SigningKey::<MlDsa44>::decode(&enc_sk);

    // Signer for SigningKey uses deterministic variant with empty context. :contentReference[oaicite:2]{index=2}
    let sig: Signature<MlDsa44> = sk.try_sign(msg).ok()?;
    let enc_sig: EncodedSignature<MlDsa44> = sig.encode();

    Some(enc_sig.as_slice().to_vec())
}

pub fn verify_44(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    let enc_pk: EncodedVerifyingKey<MlDsa44> =
        EncodedVerifyingKey::<MlDsa44>::try_from(pk_bytes).ok()?;
    let vk = VerifyingKey::<MlDsa44>::decode(&enc_pk);

    let sig = Signature::<MlDsa44>::try_from(sig_bytes).ok()?;
    vk.verify(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa44_roundtrip_sign_verify() {
        let (pk, sk) = keygen_44();
        let msg = b"hello from rhdl";

        let sig = sign_44_det(&sk, msg).expect("sign failed");
        assert!(verify_44(&pk, msg, &sig));
        assert!(!verify_44(&pk, b"tampered", &sig));
    }
}
