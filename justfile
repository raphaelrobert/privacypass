check: fmt clippy deny test

fmt:
    cargo fmt --check

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

deny:
    cargo deny check

test:
    cargo test --all-features
