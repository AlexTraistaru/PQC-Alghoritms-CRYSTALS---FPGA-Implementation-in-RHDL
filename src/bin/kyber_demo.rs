use proiect::kyber_kem::{kem_decaps, kem_encaps, kem_keypair};
use proiect::kyber_params::SYMBYTES;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn main() {
    let seed = [7u8; SYMBYTES];
    let (pk, sk) = kem_keypair(&seed);

    let mseed = [9u8; SYMBYTES];
    let (ct, ss1) = kem_encaps(&mseed, &pk);
    let ss2 = kem_decaps(&ct, &sk);

    println!("pk[0..16] = {}", hex(&pk[..16]));
    println!("ct[0..16] = {}", hex(&ct[..16]));
    println!("ss(enc)   = {}", hex(&ss1));
    println!("ss(dec)   = {}", hex(&ss2));
    println!("match     = {}", ss1 == ss2);
}
