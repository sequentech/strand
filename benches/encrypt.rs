use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use rand::rngs::OsRng;
use rand::RngCore;
use strand::backend::numb::{BigintCtx, P2048};
use strand::backend::ristretto::RistrettoCtx;
use strand::context::Ctx;
use strand::elgamal::*;
use strand::util;

fn encrypt<C: Ctx>(ctx: &C, pk: &PublicKey<C>, data: C::P, n: usize) {
    for _ in 0..n {
        let plaintext = ctx.encode(&data).unwrap();
        let randomness = ctx.rnd_exp();
        let c = pk.encrypt_ext(&plaintext, &randomness);

        let _proof = ctx.schnorr_prove(&randomness, &c.gr(), ctx.generator(), &vec![]);
    }
}

fn encrypt_ristretto(ctx: &RistrettoCtx, pk: &PublicKey<RistrettoCtx>, n: usize) {
    let mut csprng = OsRng;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    encrypt(ctx, pk, plaintext, n);
}

fn encrypt_bigint(ctx: &BigintCtx<P2048>, pk: &PublicKey<BigintCtx<P2048>>, n: usize) {
    let plaintext = ctx.rnd_exp();
    encrypt(ctx, pk, plaintext, n);
}

cfg_if::cfg_if! {
    if #[cfg(feature = "rug")] {
        use strand::backend::rug::RugCtx;
        #[cfg(feature = "rug")]
        fn encrypt_rug(ctx: &RugCtx, pk: &PublicKey<RugCtx>, n: usize) {
            let plaintext = ctx.rnd_exp();
            encrypt(ctx, pk, plaintext, n);
        }
    }
}

fn bench_encrypt(c: &mut Criterion) {
    let rctx = RistrettoCtx;
    let rsk = rctx.gen_key();
    let rpk = PublicKey::from(rsk.public_value(), &rctx);

    let bctx = BigintCtx::<P2048>::new();
    let bsk = bctx.gen_key();
    let bpk = PublicKey::from(bsk.public_value(), &bctx);

    cfg_if::cfg_if! {
        if #[cfg(feature = "rug")] {
            let gctx = RugCtx::default();
            let gsk = gctx.gen_key();
            let gpk = PublicKey::from(gsk.public_value(), &gctx);
        }
    }

    let mut group = c.benchmark_group("encrypt");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);

    for i in [10usize].iter() {
        group.bench_with_input(BenchmarkId::new("ristretto", i), i, |b, i| {
            b.iter(|| encrypt_ristretto(&rctx, &rpk, *i))
        });
        group.bench_with_input(BenchmarkId::new("bigint", i), i, |b, i| {
            b.iter(|| encrypt_bigint(&bctx, &bpk, *i))
        });
        #[cfg(feature = "rug")]
        group.bench_with_input(BenchmarkId::new("rug", i), i, |b, i| {
            b.iter(|| encrypt_rug(&gctx, &gpk, *i))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
