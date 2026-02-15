//! Bootstrap benchmark with 128-bit security parameters.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gsw_rs::bootstrap::{bootstrap, gen_evaluation_key};
use gsw_rs::params::{Params, SecurityLevel};
use gsw_rs::{encrypt, gsw_keygen, homomorphic_mult};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bootstrap_128bit(c: &mut Criterion) {
    let params = Params::new(SecurityLevel::Medium);
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let (sk, pk) = gsw_keygen(&mut rng, &params);
    let ek = gen_evaluation_key(&mut rng, &sk, &pk);
    let ct1 = encrypt(&mut rng, &pk, 1);
    let ct_noisy = homomorphic_mult(&params, &ct1, &ct1);

    c.bench_function("bootstrap_128bit", |b| {
        b.iter(|| {
            bootstrap(
                black_box(&params),
                black_box(&ct_noisy),
                black_box(&ek),
            )
        })
    });
}

fn gen_evaluation_key_128bit(c: &mut Criterion) {
    let params = Params::new(SecurityLevel::Medium);
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = gsw_keygen(&mut rng, &params);

    c.bench_function("gen_evaluation_key_128bit", |b| {
        b.iter(|| {
            let mut r = ChaCha20Rng::seed_from_u64(0);
            gen_evaluation_key(&mut r, black_box(&sk), black_box(&pk))
        })
    });
}

criterion_group!(benches, bootstrap_128bit, gen_evaluation_key_128bit);
criterion_main!(benches);
