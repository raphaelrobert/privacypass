mod batched_p384;
mod batched_ristretto255;
mod private;
mod public;

use criterion::{criterion_group, criterion_main};

use batched_p384::criterion_batched_p384_benchmark;
use batched_ristretto255::criterion_batched_ristretto255_benchmark;
use private::criterion_private_benchmark;
use public::criterion_public_benchmark;

criterion_group!(
    benches,
    criterion_private_benchmark,
    criterion_public_benchmark,
    criterion_batched_ristretto255_benchmark,
    criterion_batched_p384_benchmark
);
criterion_main!(benches);
