fn main() {
    // cycle counts measured (include done-cycle)
    let kyber_ntt: f64 = 1794.0;
    let kyber_intt: f64 = 2306.0;
    let dili_ntt: f64 = 2050.0;
    let dili_intt: f64 = 2562.0;

    // scenario frequencies in MHz
    let freqs_mhz = [100.0, 200.0, 250.0];

    println!("Latency formula: T_us = cycles / F_MHz");
    println!("Throughput formula: ops/s = (F_MHz*1e6) / cycles");
    println!();

    for f in freqs_mhz {
        let f_hz = f * 1e6;

        let k_ntt_lat_us = kyber_ntt / f;
        let k_ntt_thr = f_hz / kyber_ntt;

        let k_intt_lat_us = kyber_intt / f;
        let k_intt_thr = f_hz / kyber_intt;

        let d_ntt_lat_us = dili_ntt / f;
        let d_ntt_thr = f_hz / dili_ntt;

        let d_intt_lat_us = dili_intt / f;
        let d_intt_thr = f_hz / dili_intt;

        println!("F {:.0} MHz", f);
        println!("Kyber NTT:  latency = {:8.3} us, throughput = {:10.0} ops/s", k_ntt_lat_us, k_ntt_thr);
        println!("Kyber INTT: latency = {:8.3} us, throughput = {:10.0} ops/s", k_intt_lat_us, k_intt_thr);
        println!("Dilithium  NTT:  latency = {:8.3} us, throughput = {:10.0} ops/s", d_ntt_lat_us, d_ntt_thr);
        println!("Dilithium  INTT: latency = {:8.3} us, throughput = {:10.0} ops/s", d_intt_lat_us, d_intt_thr);
        println!();
    }
}
