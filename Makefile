CLIPPY_VERSION = 0.0.203
NIGHTLY_VERSION = nightly-2018-05-20

print-nightly-version:
	printf $(NIGHTLY_VERSION)

print-clippy-version:
	printf $(CLIPPY_VERSION)

# TODO: install-libsodium

install-rustup:
  curl https://sh.rustup.rs -sSf | sh

install-pinned-nightly:
	rustup install $(NIGHTLY_VERSION)

install-dev-tools: install-clippy install-rustfmt

install-clippy:
	cargo +$(NIGHTLY_VERSION) install clippy --version $(CLIPPY_VERSION) --force

install-rustfmt:
	rustup component add rustfmt-preview --toolchain $(NIGHTLY_VERSION)

run-lints: run-rustfmt run-clippy

run-clippy:
	cargo +$(NIGHTLY_VERSION) clippy --all --tests --all-features -- -D clippy_pedantic

run-rustfmt:
	cargo +$(NIGHTLY_VERSION) fmt --all
