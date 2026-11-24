check: fmt clippy deny test

fmt:
    cargo fmt --check

clippy:
    cargo clippy --all-targets --all-features -- -D warnings
    cargo clippy --all-targets --no-default-features --features p384 -- -D warnings
    cargo clippy --all-targets --no-default-features --features ristretto255 -- -D warnings
    cargo clippy --all-targets --no-default-features --features rsa -- -D warnings

deny:
    cargo deny check

test:
    cargo test --all-features
