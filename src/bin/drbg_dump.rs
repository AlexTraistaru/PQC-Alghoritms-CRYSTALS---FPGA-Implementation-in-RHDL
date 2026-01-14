use proiect::nist_drbg::NistDrbg;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    // seed de la count=0 din .rsp-ul tau
    let seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    let seed = unhex(seed_hex);
    let seed48: [u8; 48] = seed.try_into().unwrap();

    let mut drbg = NistDrbg::new(&seed48);

    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut m = [0u8; 32];

    drbg.randombytes(&mut d);
    drbg.randombytes(&mut z);
    drbg.randombytes(&mut m);

    println!("d (32) = {}", hex::encode(d));
    println!("z (32) = {}", hex::encode(z));
    println!("m (32) = {}", hex::encode(m));
}
