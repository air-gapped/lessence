# lessence Makefile
# Mirrors .github/workflows/ci.yml exactly — run `make ci` before pushing

.PHONY: ci fmt clippy doc build test deny check docs readme-compression install setup clean help \
       coverage fuzz fuzz-fold mutants mutants-full check-fuzz-prereqs check-mutants-prereqs \
       gate release-check distill

#---------------------------------------------------------------------------
# CI pipeline (matches GitHub Actions step-for-step)
#---------------------------------------------------------------------------

## ci: Run the full CI pipeline locally (same as GitHub Actions)
ci: fmt clippy doc test deny
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

## test: Run all tests via nextest (test profile; the release profile is for releases)
test:
	cargo nextest run

## deny: Check dependencies (advisories, licenses, bans)
deny:
	cargo deny check

#---------------------------------------------------------------------------
# Verification gates (docs/verification.md)
#---------------------------------------------------------------------------

## gate: Baseline diff + perf check before committing src/ changes (~2 min)
gate:
	./scripts/gate.sh

## release-check: Full-corpus diff + mutants + thread scaling before a release (~30 min)
release-check:
	./scripts/release-check.sh

## distill: Regenerate examples/distilled/*.log + .golden from examples/*.log
distill:
	./scripts/distill.sh

#---------------------------------------------------------------------------
# Quick checks
#---------------------------------------------------------------------------

## check: Fast pre-push validation (skip build + tests)
check: fmt clippy deny
	@echo "✓ Quick checks passed"

## docs: Regenerate the binary-derived README sections (gen: regions)
docs: build
	LESSENCE_UPDATE_DOCS=1 cargo test --release --test doc_contract

## readme-compression: Re-measure the README compression table on the local originals (local only): make readme-compression VERSION=v0.6.1
readme-compression: build
	./scripts/readme-compression.sh --write $(VERSION)

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

# Every binary `make install` puts on PATH is kept here, so a later
# before/after comparison has the real baseline instead of a guess at which
# commit was installed. Outside the tree: binaries are not repo content.
INSTALL_ARCHIVE ?= $(HOME)/.local/share/lessence/installed

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

MUTANTS_FILES := -f 'src/folder/**/*.rs' -f src/normalize.rs -f 'src/patterns/**/*.rs'

# ── Mutation testing ──────────────────────────────────────────────────
#
#   make mutants        Fast default: unit tests only.
#   make mutants-full   Thorough: all tests including integration.
#
# scripts/mutants.sh picks the worker count and memory cap from what is
# free right now and what one worker took last run; MUTANTS_RESERVE_GIB,
# MUTANTS_MEM_MAX, MUTANTS_JOBS and MUTANTS_TIMEOUT_MULT override it.
#
# -C --lib: only compile and run unit tests inside src/. Skips building
# the integration test binaries.
# ──────────────────────────────────────────────────────────────────────

## mutants: Mutation testing — fast, unit tests only (~5 min)
mutants: check-mutants-prereqs
	scripts/mutants.sh $(MUTANTS_FILES) -C --lib

## mutants-full: Mutation testing — thorough, all tests (~15 min)
mutants-full: check-mutants-prereqs
	scripts/mutants.sh $(MUTANTS_FILES)

#---------------------------------------------------------------------------
# Install
#---------------------------------------------------------------------------

## install: Build and install to ~/.cargo/bin, keeping a copy of every build installed
install: build
	@mkdir -p $(INSTALL_ARCHIVE)
	@v=$$(./target/release/lessence --version | awk '{print $$2}'); \
	 sha=$$(git rev-parse --short=9 HEAD); \
	 dirty=$$(git diff --quiet HEAD 2>/dev/null || echo -dirty); \
	 dest=$(INSTALL_ARCHIVE)/lessence-$$v-$$sha$$dirty; \
	 cp -f ./target/release/lessence $$dest; \
	 echo "archived $$dest"
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
