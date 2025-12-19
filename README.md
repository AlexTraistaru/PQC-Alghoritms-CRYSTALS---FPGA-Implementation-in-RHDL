# Post-Quantum Cryptography in RHDL (Kyber & Dilithium)

Acest proiect reprezintă o implementare a algoritmilor criptografici post-cuantici Crystals-Kyber și Crystals-Dilithium, adaptată pentru sinteză hardware (FPGA) folosind limbajul RHDL. Implementarea este organizată modular pentru a facilita înțelegerea, testarea și reutilizarea componentelor.

Codul este organizat în module distincte pentru fiecare algoritm.
1. Kyber - Mecanism de Încapsulare a Cheilor
    # kyber_ntt_rhdl.rs

        Nucleul Hardware (Core): Implementează transformarea NTT (Number Theoretic Transform) folosind o Mașină de Stări Finită (FSM).

        Include un model de memorie Dual-Port BRAM pentru stocarea coeficienților.

        Gestionează stările Idle, Run (procesare "butterfly cores" Cooley-Tukey/Gentleman-Sande), InvScale și Done.

   # kyber_arith_rhdl.rs

        Unități aritmetice de bază (#[kernel]).

        Include reducerea Montgomery, reducerea Barrett, adunarea și scăderea modulară.

   # kyber_poly.rs

        Gestionează structurile de date polinomiale și interfața cu nucleul NTT.

   # kyber_indcpa.rs

        Implementează schema de criptare simetrică de bază IND-CPA.

  # kyber_kem.rs

        Protocolul final KEM construit peste IND-CPA.

        Implementează transformarea Fujisaki-Okamoto pentru securitate CCA (Chosen Ciphertext Attack).

   # kyber_params.rs si src/zetas_kyber.rs

        Definesc constantele globale (N=256,Q=3329) și tabelele precalculate pentru factorii de rotație (twiddle factors).

2. Dilithium - Semnătură Digitală

  #  dilithium_ntt.rs

        Similar cu Kyber, conține nucleul hardware pentru NTT specific Dilithium (Q=8380417).

        Implementează FSM-ul complet pentru transformări ntt și intt (inverse), folosind o arhitectură de memorie și procesare iterativă.

  #  dilithium_arith.rs si dilithium_reduce.rs

        Aritmetică modulară.

        Funcții de descompunere (decompose), rotunjire (power2round) și verificare a normelor (norm_bound).

   # dilithium_sample.rs

        Generarea deterministă a matricelor și vectorilor folosind SHAKE-128/256.

   # dilithium_poly.rs si dilithium_pack.rs

        Manipularea vectorilor și matricelor de polinoame (PolyVec, PolyMat).

        Împachetarea eficientă a biților pentru chei și semnături.

   # dilithium.rs

        Implementarea procedurilor de nivel înalt: keygen, sign și verify.

3. Fisiere comune

   # keccak.rs

        Implementarea low-level a permutării Keccak-f, motorul din spatele SHA3.

   # shake.rs

        Implementarea funcțiilor de extensie SHAKE128 și SHAKE256, utilizate extensiv în ambii algoritmi pentru generarea numerelor pseudo-aleatoare.

