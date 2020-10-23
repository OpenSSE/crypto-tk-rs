use criterion::{criterion_group, criterion_main, Criterion};

mod prf_benches {
    use super::*;
    use crypto_tk_rs::Prf;

    pub fn prf(c: &mut Criterion) {
        macro_rules! prf_bench {
            ($size:expr) => {{
                let prf = Prf::new();
                let in_buffer = [0u8; 16];
                let mut out_buffer = [0u8; $size];
                c.bench_function(&format!("prf_{}_bytes", $size), |b| {
                    b.iter(|| prf.fill_bytes(&in_buffer, &mut out_buffer))
                });
            }};
        }

        prf_bench!(16);
        prf_bench!(32);
        prf_bench!(64);
        prf_bench!(128);
        prf_bench!(256);
        prf_bench!(512);
    }

    criterion_group!(benches, prf);
}

mod prg_benches {
    use super::*;
    use crypto_tk_rs::Prg;

    pub fn prg(c: &mut Criterion) {
        macro_rules! prg_bench {
            ($size:expr) => {{
                let prg = Prg::new();
                let mut out_buffer = [0u8; $size];
                c.bench_function(&format!("prg_{}_bytes", $size), |b| {
                    b.iter(|| prg.fill_pseudo_random_bytes(&mut out_buffer))
                });
            }};
        }

        // let prf = Prg::new();
        // let mut out_buffer = vec![0u8; 16];
        // c.bench_function(&format!("prg_{}_bytes", 16), |b| {
        //     b.iter(|| prg.fill_pseudo_random_bytes(&mut out_buffer))
        // });

        prg_bench!(16);
        prg_bench!(32);
        prg_bench!(64);
        prg_bench!(128);
        prg_bench!(256);
        prg_bench!(512);
    }

    criterion_group!(benches, prg);
}

criterion_main!(prf_benches::benches, prg_benches::benches);
