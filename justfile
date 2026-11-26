check: fmt clippy deny test

fmt:
    cargo fmt --check

clippy:
    cargo hack clippy --feature-powerset --at-least-one-of rsa,p384,ristretto255 --clean-per-run --no-dev-deps -- -D warnings

deny:
    cargo deny check

test:
    cargo test --all-features
