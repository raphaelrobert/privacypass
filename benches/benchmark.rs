mod amortized;
mod private;
mod public;

use criterion::{criterion_group, criterion_main};

use amortized::{criterion_amortized_p384_benchmark, criterion_amortized_ristretto255_benchmark};
use private::{criterion_private_p384_benchmark, criterion_private_ristretto255_benchmark};
use public::criterion_public_benchmark;

criterion_group!(
    benches,
    criterion_private_p384_benchmark,
    criterion_private_ristretto255_benchmark,
    criterion_public_benchmark,
    criterion_amortized_ristretto255_benchmark,
    criterion_amortized_p384_benchmark
);
criterion_main!(benches);
