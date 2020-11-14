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

mod rcprf_benches {
    use super::*;
    use crypto_tk_rs::rcprf::*;
    use crypto_tk_rs::RCPrfRange;

    const RCPRF_HEIGHT: u8 = 48;
    pub fn rcprf_iter_eval(c: &mut Criterion) {
        macro_rules! rcprf_iter_eval_bench {
            ($size:expr) => {{
                let rcprf = RCPrf::new(RCPRF_HEIGHT).unwrap();

                let mut out = [0u8; 16];
                c.bench_function(
                    &format!("rcprf_iter_eval_width_{}", $size),
                    |b| {
                        b.iter(|| {
                            for x in 0..$size {
                                rcprf.eval(x, &mut out).unwrap();
                            }
                        });
                    },
                );
            }};
        }

        rcprf_iter_eval_bench!(16);
        rcprf_iter_eval_bench!(32);
        rcprf_iter_eval_bench!(512);
    }
    pub fn rcprf_range_eval(c: &mut Criterion) {
        macro_rules! rcprf_range_eval_bench {
            ($size:expr) => {{
                let rcprf = RCPrf::new(RCPRF_HEIGHT).unwrap();
                let mut outs = vec![[0u8; 16]; $size];
                let mut slice: Vec<&mut [u8]> =
                    outs.iter_mut().map(|x| &mut x[..]).collect();

                c.bench_function(
                    &format!("rcprf_range_eval_width_{}", $size),
                    |b| {
                        b.iter(|| {
                            rcprf
                                .eval_range(
                                    &RCPrfRange::from(0..$size),
                                    &mut slice,
                                )
                                .unwrap();
                        });
                    },
                );
            }};
        }

        rcprf_range_eval_bench!(16);
        rcprf_range_eval_bench!(32);
        rcprf_range_eval_bench!(512);
        rcprf_range_eval_bench!(4096);
    }
    pub fn rcprf_par_range_eval(c: &mut Criterion) {
        macro_rules! rcprf_par_range_eval_bench {
            ($size:expr) => {{
                let rcprf = RCPrf::new(RCPRF_HEIGHT).unwrap();
                let mut outs = vec![[0u8; 16]; $size];
                let mut slice: Vec<&mut [u8]> =
                    outs.iter_mut().map(|x| &mut x[..]).collect();

                c.bench_function(
                    &format!("rcprf_par_range_eval_width_{}", $size),
                    |b| {
                        b.iter(|| {
                            rcprf
                                .par_eval_range(
                                    &RCPrfRange::from(0..$size),
                                    &mut slice,
                                )
                                .unwrap();
                        });
                    },
                );
            }};
        }

        rcprf_par_range_eval_bench!(16);
        rcprf_par_range_eval_bench!(32);
        rcprf_par_range_eval_bench!(512);
        rcprf_par_range_eval_bench!(4096);
    }

    pub fn rcprf_iter_range_eval(c: &mut Criterion) {
        let rcprf = RCPrf::new(RCPRF_HEIGHT).unwrap();

        c.bench_function("rcprf_iter_range_eval", |b| {
            b.iter(|| {
                let _: Vec<Vec<u8>> = rcprf
                    .index_value_iter_range(&RCPrfRange::from(0..4096), 16)
                    .unwrap()
                    .map(|(_, v)| v)
                    .collect();
            });
        });
    }

    criterion_group!(
        benches,
        rcprf_iter_eval,
        rcprf_range_eval,
        rcprf_par_range_eval,
        rcprf_iter_range_eval
    );
}

criterion_main!(
    prf_benches::benches,
    prg_benches::benches,
    rcprf_benches::benches
);
