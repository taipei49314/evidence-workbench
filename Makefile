.PHONY: check install-local

check:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --all-features --all-targets
	if test -f tests/harness/Cargo.toml; then cargo test --manifest-path tests/harness/Cargo.toml; fi

install-local:
	cargo install --path . --locked --force
