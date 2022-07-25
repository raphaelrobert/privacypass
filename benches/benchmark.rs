mod batched;
mod private;
mod public;

use criterion::{criterion_group, criterion_main};

use batched::*;
use private::*;
use public::*;

criterion_group!(
    benches,
    criterion_private_benchmark,
    criterion_public_benchmark,
    criterion_batched_benchmark
);
criterion_main!(benches);
