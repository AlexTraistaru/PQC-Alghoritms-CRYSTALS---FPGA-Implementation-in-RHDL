use rhdl::prelude::*;

// KYBER 
use proiect::kyber_ntt::{ntt_step as kyber_step, NttIn as KyberIn, NttState as KyberState, Coeff as KyberCoeff};

// DILITHIUM 
use proiect::dilithium_ntt::{ntt_step as dili_step, NttIn as DiliIn, NttState as DiliState, Coeff as DiliCoeff};
use proiect::dilithium_params::N as DILI_N;

// KYBER runner 

fn kyber_cycles(inverse: bool) -> u64 {
    // Kyber N = 256
    let mut mem: [KyberCoeff; 256] = [signed::<U16>(0); 256];

    // BRAM read-address regs (1-cycle latency)
    let mut ra: u8 = 0;
    let mut rb: u8 = 0;

    let mut st = KyberState::default();
    let mut cycles: u64 = 0;
    let mut start = true; // pulse 1 cycle

    loop {
        // Data appears from previous cycle addresses (BRAM 1-cycle)
        let rdata_a = mem[ra as usize];
        let rdata_b = mem[rb as usize];

        let inp = KyberIn {
            start,
            inverse,
            rdata_a,
            rdata_b,
        };

        let (nst, out) = kyber_step(st, inp);

        // Apply writes at end of cycle
        if out.porta.we {
            mem[out.porta.addr.raw() as usize] = out.porta.wdata;
        }
        if out.portb.we {
            mem[out.portb.addr.raw() as usize] = out.portb.wdata;
        }

        // Latch addresses for next cycle read
        ra = out.porta.addr.raw() as u8;
        rb = out.portb.addr.raw() as u8;

        cycles += 1;
        start = false;
        st = nst;

        if out.done {
            break;
        }
        if cycles > 2_000_000 {
            panic!("Kyber NTT stuck");
        }
    }

    cycles
}

// DILITHIUM runner 

fn dilithium_cycles(inverse: bool) -> u64 {
    // Dilithium N (în params) = 256
    let n = DILI_N;
    assert_eq!(n, 256, "Runner assumes N=256");

    let mut mem: [DiliCoeff; 256] = [signed::<U32>(0); 256];

    let mut ra: u8 = 0;
    let mut rb: u8 = 0;

    let mut st = DiliState::default();
    let mut cycles: u64 = 0;
    let mut start = true;

    loop {
        let rdata_a = mem[ra as usize];
        let rdata_b = mem[rb as usize];

        let inp = DiliIn {
            start,
            inverse,
            rdata_a,
            rdata_b,
        };

        let (nst, out) = dili_step(st, inp);

        if out.porta.we {
            mem[out.porta.addr.raw() as usize] = out.porta.wdata;
        }
        if out.portb.we {
            mem[out.portb.addr.raw() as usize] = out.portb.wdata;
        }

        ra = out.porta.addr.raw() as u8;
        rb = out.portb.addr.raw() as u8;

        cycles += 1;
        start = false;
        st = nst;

        if out.done {
            break;
        }
        if cycles > 5_000_000 {
            panic!("Dilithium NTT stuck");
        }
    }

    cycles
}

fn main() {
    // Kyber
    let k_fwd = kyber_cycles(false);
    let k_inv = kyber_cycles(true);

    // Dilithium
    let d_fwd = dilithium_cycles(false);
    let d_inv = dilithium_cycles(true);

    println!("Cicluri numarate");
    println!("Kyber     NTT  cycles = {k_fwd}");
    println!("Kyber     INTT cycles = {k_inv}");
    println!("Dilithium NTT  cycles = {d_fwd}");
    println!("Dilithium INTT cycles = {d_inv}");
}
