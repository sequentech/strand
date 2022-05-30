use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use strand::backend::num_bigint::BigintCtx;
use strand::backend::ristretto::RistrettoCtx;
#[cfg(feature = "rug")]
use strand::backend::rug::RugCtx;
use strand::context::Ctx;
use strand::elgamal::*;
use strand::shuffler::*;
use strand::util;

fn test_shuffle_generic<C: Ctx>(ctx: C, n: usize) {
    let sk = ctx.gen_key();
    let pk = PublicKey::from(sk.public_value(), &ctx);

    let es = util::random_ballots(n, &ctx);
    let seed = vec![];
    let hs = ctx.generators(es.len() + 1, 0, &seed);
    let shuffler = Shuffler::new(&pk, &hs, &ctx);

    let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);
    let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm, &vec![]);
    let ok = shuffler.check_proof(&proof, &es, &e_primes, &vec![]);

    assert!(ok);
}

fn shuffle_ristretto(n: usize) {
    let ctx = RistrettoCtx;
    test_shuffle_generic(ctx, n);
}

fn shuffle_bigint(n: usize) {
    let ctx = BigintCtx::default();
    test_shuffle_generic(ctx, n);
}

#[cfg(feature = "rug")]
fn shuffle_rug(n: usize) {
    let ctx = RugCtx::default();
    test_shuffle_generic(ctx, n);
}

fn bench_shuffle(c: &mut Criterion) {
    let mut group = c.benchmark_group("shuffle");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);

    for i in [100usize].iter() {
        group.bench_with_input(BenchmarkId::new("ristretto", i), i, |b, i| {
            b.iter(|| shuffle_ristretto(*i * 10))
        });
        group.bench_with_input(BenchmarkId::new("bigint", i), i, |b, i| {
            b.iter(|| shuffle_bigint(*i))
        });
        #[cfg(feature = "rug")]
        group.bench_with_input(BenchmarkId::new("rug", i), i, |b, i| {
            b.iter(|| shuffle_rug(*i))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_shuffle);
criterion_main!(benches);
