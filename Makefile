# lessence Makefile
# Mirrors .github/workflows/ci.yml exactly — run `make ci` before pushing

.PHONY: ci fmt clippy doc build test deny check install setup clean help fuzz mutants

#---------------------------------------------------------------------------
# CI pipeline (matches GitHub Actions step-for-step)
#---------------------------------------------------------------------------

## ci: Run the full CI pipeline locally (same as GitHub Actions)
ci: fmt clippy doc build test deny
	@echo "✓ All CI checks passed"

## fmt: Check formatting (cargo fmt --check)
fmt:
	cargo fmt --all -- --check

## clippy: Run clippy with warnings as errors
clippy:
	cargo clippy --all-targets -- -D warnings

## doc: Build docs with warnings as errors
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

## build: Build release binary
build:
	cargo build --release

## test: Run all tests via nextest (release mode)
test:
	cargo nextest run --release

## deny: Check dependencies (advisories, licenses, bans)
deny:
	cargo deny check

#---------------------------------------------------------------------------
# Quick checks
#---------------------------------------------------------------------------

## check: Fast pre-push validation (skip build + tests)
check: fmt clippy deny
	@echo "✓ Quick checks passed"

## test-unit: Run unit tests only (fast)
test-unit:
	cargo test --lib

#---------------------------------------------------------------------------
# Local-only heavy testing (not in CI)
#---------------------------------------------------------------------------

## fuzz: Run fuzz testing on normalizer (requires nightly, local only, 5 min default)
fuzz:
	cargo +nightly fuzz run fuzz_normalize -- -max_total_time=300

## fuzz-fold: Run fuzz testing on full folding pipeline (requires nightly, local only)
fuzz-fold:
	cargo +nightly fuzz run fuzz_fold -- -max_total_time=300

## mutants: Run mutation testing on core modules (local only, ~10-20 min)
mutants:
	cargo mutants -f src/folder.rs -f src/normalize.rs -- --lib

#---------------------------------------------------------------------------
# Install
#---------------------------------------------------------------------------

## install: Build and install to ~/.cargo/bin
install: build
	cp ./target/release/lessence ~/.cargo/bin/lessence
	@lessence --version

## setup: Install required development tools
setup:
	@echo "Installing development tools..."
	cargo install cargo-deny
	curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ~/.cargo/bin
	rustup component add clippy rustfmt
	@echo ""
	@echo "✓ Tools installed:"
	@cargo deny --version
	@cargo nextest --version
	@cargo clippy --version
	@cargo fmt --version

## clean: Remove build artifacts
clean:
	cargo clean

#---------------------------------------------------------------------------
# Help
#---------------------------------------------------------------------------

## help: Show this help
help:
	@echo "lessence Development Commands"
	@echo ""
	@echo "  make ci        — Run full CI pipeline (same as GitHub Actions)"
	@echo "  make check     — Quick pre-push validation (fmt + clippy + deny)"
	@echo "  make fuzz      — Fuzz normalizer (nightly, local only, 5 min)"
	@echo "  make mutants   — Mutation testing on core modules (local only)"
	@echo "  make setup     — Install required dev tools"
	@echo "  make install   — Build and install to PATH"
	@echo ""
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/ /'
