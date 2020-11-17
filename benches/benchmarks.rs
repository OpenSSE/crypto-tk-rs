use criterion::BenchmarkId;
use criterion::Throughput;
use criterion::{criterion_group, criterion_main, Criterion};

mod prf_benches {
    use super::*;
    use crypto_tk_rs::Prf;

    pub fn prf(c: &mut Criterion) {
        let prf = Prf::new();
        let in_buffer = [0u8; 16];

        let mut group = c.benchmark_group("prf_eval");
        for size in [16, 32, 64, 128, 256, 512].iter() {
            let mut out_buffer = vec![0u8; *size];
            group.throughput(Throughput::Elements(1));
            group.bench_with_input(
                BenchmarkId::from_parameter(size),
                size,
                |b, &_size| {
                    b.iter(|| prf.fill_bytes(&in_buffer, &mut out_buffer))
                },
            );
        }
        group.finish();
    }

    criterion_group!(benches, prf);
}

mod prg_benches {
    use super::*;
    use crypto_tk_rs::Prg;

    const PRG_BENCH_SIZES: [u64; 4] = [16, 32, 512, 4096];

    pub fn prg(c: &mut Criterion) {
        let prg = Prg::new();
        let mut group = c.benchmark_group("prg_eval");
        for size in &PRG_BENCH_SIZES {
            let mut out_buffer = vec![0u8; *size as usize];
            group.throughput(Throughput::Bytes(*size));
            group.bench_with_input(
                BenchmarkId::from_parameter(size),
                size,
                |b, &_size| {
                    b.iter(|| prg.fill_pseudo_random_bytes(&mut out_buffer))
                },
            );
        }
        group.finish();
    }

    criterion_group!(benches, prg);
}

mod rcprf_benches {
    use super::*;
    use crypto_tk_rs::rcprf::*;
    use crypto_tk_rs::RCPrfRange;

    const RCPRF_BENCH_SIZES: [u64; 4] = [16, 32, 512, 4096];

    const RCPRF_HEIGHT: u8 = 48;
    pub fn rcprf_multiple_eval(c: &mut Criterion) {
        let rcprf = RCPrf::new(RCPRF_HEIGHT).unwrap();

        let mut out = [0u8; 16];
        let mut group = c.benchmark_group("rcprf_mult_eval");
        for size in &RCPRF_BENCH_SIZES {
            group.throughput(Throughput::Bytes(*size));
            group.bench_with_input(
                BenchmarkId::from_parameter(size),
                size,
                |b, &size| {
                    b.iter(|| {
                        for x in 0..size {
                            rcprf.eval(x, &mut out).unwrap();
                        }
                    });
                },
            );
        }

        group.finish();
    }
    pub fn rcprf_range_eval(c: &mut Criterion) {
        let rcprf = RCPrf::new(RCPRF_HEIGHT).unwrap();

        let mut outs =
            vec![[0u8; 16]; *RCPRF_BENCH_SIZES.iter().max().unwrap() as usize];
        let mut slice: Vec<&mut [u8]> =
            outs.iter_mut().map(|x| &mut x[..]).collect();

        let mut group = c.benchmark_group("rcprf_range_eval");
        for size in &RCPRF_BENCH_SIZES {
            group.throughput(Throughput::Bytes(*size));
            group.bench_with_input(
                BenchmarkId::from_parameter(size),
                size,
                |b, &size| {
                    b.iter(|| {
                        rcprf
                            .eval_range(
                                &RCPrfRange::from(0..size as u64),
                                &mut slice[..size as usize],
                            )
                            .unwrap();
                    });
                },
            );
        }

        group.finish();
    }

    pub fn rcprf_par_range_eval(c: &mut Criterion) {
        let rcprf = RCPrf::new(RCPRF_HEIGHT).unwrap();

        let mut outs =
            vec![[0u8; 16]; *RCPRF_BENCH_SIZES.iter().max().unwrap() as usize];
        let mut slice: Vec<&mut [u8]> =
            outs.iter_mut().map(|x| &mut x[..]).collect();

        let mut group = c.benchmark_group("rcprf_par_range_eval");
        for size in &RCPRF_BENCH_SIZES {
            group.throughput(Throughput::Elements(*size));
            group.bench_with_input(
                BenchmarkId::from_parameter(size),
                size,
                |b, &size| {
                    b.iter(|| {
                        rcprf
                            .par_eval_range(
                                &RCPrfRange::from(0..size as u64),
                                &mut slice[..size as usize],
                            )
                            .unwrap();
                    });
                },
            );
        }

        group.finish();
    }

    pub fn rcprf_iter_range_eval(c: &mut Criterion) {
        let rcprf = RCPrf::new(RCPRF_HEIGHT).unwrap();

        let mut group = c.benchmark_group("rcprf_iter_range_eval");
        for size in &RCPRF_BENCH_SIZES {
            group.throughput(Throughput::Elements(*size));
            group.bench_with_input(
                BenchmarkId::from_parameter(size),
                size,
                |b, &size| {
                    b.iter(|| {
                        let _: Vec<Vec<u8>> = rcprf
                            .index_value_iter_range(
                                &RCPrfRange::from(0..size as u64),
                                16,
                            )
                            .unwrap()
                            .map(|(_, v)| v)
                            .collect();
                    });
                },
            );
        }

        group.finish();
    }

    criterion_group!(
        benches,
        rcprf_multiple_eval,
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
