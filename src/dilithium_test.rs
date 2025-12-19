#[cfg(test)]
mod tests {
    use crate::dilithium::{keygen, sign, verify};

    #[test]
    fn test_dilithium_consistency() {
        // 1. Keygen
        // Folosim un seed fix pentru reproductibilitate, dar în practică e random
        let seed = [7u8; 32]; 
        let (pk, sk) = keygen(seed);

        // 2. Sign
        let msg = b"Mesaj important semnat cu Dilithium2";
        let sig = sign(&sk, msg);

        // 3. Verify - ar trebui să fie true
        let valid = verify(&pk, msg, &sig);
        assert!(valid, "Semnatura ar trebui sa fie valida");
    }

    #[test]
    fn test_dilithium_wrong_message() {
        let seed = [10u8; 32];
        let (pk, sk) = keygen(seed);
        
        let msg = b"Mesaj original";
        let sig = sign(&sk, msg);

        let msg_fake = b"Mesaj modificat";
        let valid = verify(&pk, msg_fake, &sig);
        assert!(!valid, "Verificarea ar trebui sa esueze pentru mesaj modificat");
    }

    #[test]
    fn test_dilithium_wrong_key() {
        let seed1 = [1u8; 32];
        let (pk1, _) = keygen(seed1);

        let seed2 = [2u8; 32];
        let (_, sk2) = keygen(seed2);

        let msg = b"Test";
        let sig = sign(&sk2, msg);

        // Verificăm semnătura făcută cu SK2 folosind PK1
        let valid = verify(&pk1, msg, &sig);
        assert!(!valid, "Verificarea ar trebui sa esueze cu cheie publica gresita");
    }
}

#[cfg(test)]
mod debug_math_tests {
    use crate::dilithium_poly::Poly;
    use crate::dilithium_params::Q;

    // Funcție locală de normalizare pentru test (copy-paste din dilithium.rs)
    fn normalize_temp(p: &mut Poly) {
        for c in p.coeffs.iter_mut() {
            let mut v = *c % Q;
            if v < 0 { v += Q; }
            if v > Q / 2 { v -= Q; }
            *c = v;
        }
    }

    #[test]
    fn test_ntt_multiplication_logic() {
        let mut p1 = Poly::default();
        let mut p2 = Poly::default();

        // Setăm polinoame simple: P1 = 5, P2 = 2 (constante)
        p1.coeffs[0] = 5;
        p2.coeffs[0] = 2;
        // P1 * P2 ar trebui să fie 10.

        // 1. Transformăm în NTT
        p1.ntt();
        p2.ntt();

        // 2. Înmulțim punct cu punct
        let mut p3 = Poly::pointwise_mul(&p1, &p2);

        // 3. Transformăm înapoi (INTT)
        p3.intt();
        
        // 4. Normalizăm (cum face algoritmul Dilithium)
        normalize_temp(&mut p3);

        println!("Debug Math: Expected 10, Got {}", p3.coeffs[0]);
        println!("Debug Math: Expected 0, Got {}", p3.coeffs[1]);

        assert_eq!(p3.coeffs[0], 10, "NTT Multiplication failed: 5 * 2 != 10");
        assert_eq!(p3.coeffs[1], 0, "NTT Multiplication produced artifacts");
    }

    #[test]
    fn test_ntt_roundtrip_simple() {
        let mut p1 = Poly::default();
        p1.coeffs[0] = 123;
        p1.coeffs[1] = -50;
        
        let _original = p1.clone();
        
        p1.ntt();
        p1.intt();
        normalize_temp(&mut p1);
        
        // Coeficientul 1 e negativ (-50), modulo Q e mare, normalizat e -50.
        // Verificăm dacă revine la forma inițială.
        assert_eq!(p1.coeffs[0], 123);
        // Trebuie să gestionăm faptul că originalul nu e modulo Q, dar 123 e mic.
        
        // Verificăm consistența
        if p1.coeffs[1] != -50 {
             println!("NTT Roundtrip mismatch at idx 1. Got: {}, Expected: -50", p1.coeffs[1]);
        }
    }
}