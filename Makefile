.PHONY: all test fmt fmt-check clippy clean ios setup-ios-targets

all: fmt-check clippy test

test:
	cargo test --workspace --all-features

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

clean:
	cargo clean
	rm -rf ios/bindings/ ios/LedgerSolCore.xcframework

ios:
	./ios/build-xcframework.sh

setup-ios-targets:
	rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
