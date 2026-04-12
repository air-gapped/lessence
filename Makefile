# lessence Makefile
# Mirrors .github/workflows/ci.yml exactly — run `make ci` before pushing

.PHONY: ci fmt clippy doc build test deny check install setup clean help \
       coverage fuzz fuzz-fold mutants mutants-full check-fuzz-prereqs check-mutants-prereqs

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

## coverage: Generate HTML coverage report (opens in browser)
coverage:
	@cargo llvm-cov --version >/dev/null 2>&1 || { echo "Requires: cargo install cargo-llvm-cov"; exit 1; }
	cargo llvm-cov nextest --no-fail-fast --html --ignore-filename-regex 'tests/'
	@echo "Report: target/llvm-cov/html/index.html"

#---------------------------------------------------------------------------
# Local-only heavy testing (not in CI)
# All targets run at low priority (nice) to keep the system responsive.
# Override defaults: make fuzz FUZZ_TIME=600 FUZZ_WORKERS=4
#---------------------------------------------------------------------------

FUZZ_TIME ?= 300
FUZZ_WORKERS ?= 1

check-fuzz-prereqs:
	@cargo +nightly fuzz --version >/dev/null 2>&1 || { echo "Requires: cargo install cargo-fuzz && rustup toolchain install nightly"; exit 1; }

check-mutants-prereqs:
	@cargo mutants --version >/dev/null 2>&1 || { echo "Requires: cargo install cargo-mutants"; exit 1; }

## fuzz: Fuzz normalizer (nightly, local only, FUZZ_TIME=300 FUZZ_WORKERS=1)
fuzz: check-fuzz-prereqs
	nice -n 19 cargo +nightly fuzz run fuzz_normalize -- -max_total_time=$(FUZZ_TIME) -jobs=$(FUZZ_WORKERS) -workers=$(FUZZ_WORKERS)

## fuzz-fold: Fuzz full folding pipeline (nightly, local only, FUZZ_TIME=300 FUZZ_WORKERS=1)
fuzz-fold: check-fuzz-prereqs
	nice -n 19 cargo +nightly fuzz run fuzz_fold -- -max_total_time=$(FUZZ_TIME) -jobs=$(FUZZ_WORKERS) -workers=$(FUZZ_WORKERS)

MUTANTS_MEM_MAX ?= 32G
MUTANTS_TIMEOUT_MULT ?= 3
MUTANTS_RUN := systemd-run --scope -p MemoryMax=$(MUTANTS_MEM_MAX) nice -n 19
MUTANTS_ENV := PROPTEST_CASES=32 PROPTEST_MAX_SHRINK_ITERS=100
MUTANTS_FILES := -f src/folder.rs -f src/normalize.rs -f 'src/patterns/**/*.rs'

# ── Mutation testing targets ──────────────────────────────────────────
#
#   make mutants        Fast default. Builds & runs only unit tests.
#                       ~0.7s per mutant ≈ 12 min for ~1,000 mutants.
#                       Unit tests catch >99% of mutants.
#
#   make mutants-full   Thorough. Builds & runs ALL tests including
#                       integration (subprocess) tests.
#                       ~2.3s per mutant ≈ 38 min for ~1,000 mutants.
#                       Use before releases to verify nothing slips
#                       through that unit tests miss.
#
# Both targets:
#   - Use [profile.mutants] (opt-level=1, debug=none) for fast builds
#   - Reduce proptest from 256 → 32 cases (PROPTEST_CASES)
#   - Run at low priority (nice) under memory limit (systemd-run)
#   - Cap lints to skip warning checks on mutated code
#
# How it works: cargo-mutants changes one operator at a time in the
# source, rebuilds, runs tests, checks if any test fails. If no test
# fails, the mutant "survived" — meaning your tests have a gap.
#
# -C --lib tells cargo to only compile and run the #[test] functions
# inside src/ (the library). Without it, cargo also compiles and links
# 5 extra test binaries from tests/ — adding ~1.5s per mutant for
# integration tests that rarely catch anything unit tests miss.
# ──────────────────────────────────────────────────────────────────────

## mutants: Mutation testing — fast, unit tests only (~12 min)
mutants: check-mutants-prereqs
	$(MUTANTS_RUN) env $(MUTANTS_ENV) cargo mutants --in-place \
		--timeout-multiplier $(MUTANTS_TIMEOUT_MULT) \
		$(MUTANTS_FILES) -C --lib

## mutants-full: Mutation testing — thorough, all tests (~38 min)
mutants-full: check-mutants-prereqs
	$(MUTANTS_RUN) env $(MUTANTS_ENV) cargo mutants --in-place \
		--timeout-multiplier $(MUTANTS_TIMEOUT_MULT) \
		$(MUTANTS_FILES)

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
	@echo "  make ci            — Run full CI pipeline (same as GitHub Actions)"
	@echo "  make check         — Quick pre-push validation (fmt + clippy + deny)"
	@echo "  make coverage      — HTML code coverage report (unit tests)"
	@echo "  make fuzz          — Fuzz normalizer (nightly, local only, 5 min)"
	@echo "  make mutants       — Mutation testing, unit tests only (~12 min)"
	@echo "  make mutants-full  — Mutation testing, all tests (~38 min)"
	@echo "  make setup         — Install required dev tools"
	@echo "  make install       — Build and install to PATH"
	@echo ""
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/ /'
