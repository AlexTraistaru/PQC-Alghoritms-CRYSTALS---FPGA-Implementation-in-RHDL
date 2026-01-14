// Prints a Markdown table with latency/throughput for the measured cycle counts.

fn main() {
    // Measured (include done-cycle) from your runner:
    let kyber_ntt: f64 = 1794.0;
    let kyber_intt: f64 = 2306.0;
    let dili_ntt: f64 = 2050.0;
    let dili_intt: f64 = 2562.0;

    let freqs_mhz = [100.0, 200.0, 250.0];

    println!("| Core | Cycles | F (MHz) | Latency (us) | Throughput (ops/s) |");

    for &f in &freqs_mhz {
        let f_hz = f * 1e6;

        for (name, c) in [
            ("Kyber NTT", kyber_ntt),
            ("Kyber INTT", kyber_intt),
            ("Dilithium NTT", dili_ntt),
            ("Dilithium INTT", dili_intt),
        ] {
            let lat_us = c / f;
            let thr = f_hz / c;
            println!("| {}  | {}  | {}  | {:.3}   | {:.0} |", name, c as u64, f as u64, lat_us, thr);
        }
    }
}
