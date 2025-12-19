use proiect::dilithium::{keygen, sign, verify};

fn main() {
    println!("--- Start Dilithium2 Demo ---");

    // 1. Keygen
    let seed = [1u8; 32];
    println!("Generare chei...");
    let (pk, sk) = keygen(seed);

    // 2. Sign
    let msg = b"dilithium2 full demo";
    println!("Semnare mesaj: '{:?}'", std::str::from_utf8(msg).unwrap());
    let sig = sign(&sk, msg);

    // 3. Verify (Cazul Valid)
    let ok = verify(&pk, msg, &sig);
    println!("Verificare semnatura valida: {}", ok);

    // 4. Verify (Cazul Invalid / Tampering)
    // Încercăm să verificăm semnătura originală pe un mesaj modificat
    let msg_fake = b"dilithium2 full demo (HACKED)";
    let ok_fake = verify(&pk, msg_fake, &sig);
    println!("Verificare mesaj modificat (trebuie false): {}", ok_fake);
    
    // Verificare finală
    if ok && !ok_fake {
        println!("SUCCESS: Dilithium functioneaza perfect!");
    } else {
        println!("FAILURE: Ceva nu e in regula.");
    }
}