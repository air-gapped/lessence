# lessence Makefile
# Common development tasks

.PHONY: build test test-unit test-integration test-security bench lint audit clean setup help

# Configuration
BINARY := lessence

#---------------------------------------------------------------------------
# Setup
#---------------------------------------------------------------------------

## setup: Configure git hooks and dev environment
setup:
	git config core.hooksPath .githooks
	@echo "Git hooks configured"

#---------------------------------------------------------------------------
# Build
#---------------------------------------------------------------------------

## build: Build release binary
build:
	cargo build --release

## clean: Remove build artifacts
clean:
	cargo clean

#---------------------------------------------------------------------------
# Test
#---------------------------------------------------------------------------

## test: Run all tests (release mode — required for timing assertions)
test:
	cargo test --release

## test-unit: Run unit tests only
test-unit:
	cargo test --lib

## test-integration: Run integration tests only
test-integration:
	cargo test --tests --release

## test-security: Run security/ReDoS tests
test-security:
	cargo test --release --test test_ipv6_evil_patterns

## bench: Run performance/detection benchmarks
bench:
	cargo test --release --test test_detection_performance -- --nocapture

#---------------------------------------------------------------------------
# Quality
#---------------------------------------------------------------------------

## lint: Run clippy (or warn-as-error build if clippy unavailable)
lint:
	@if command -v cargo-clippy >/dev/null 2>&1 || cargo clippy --version >/dev/null 2>&1; then \
		cargo clippy --all-targets -- -D warnings; \
	else \
		echo "clippy not found, falling back to RUSTFLAGS=-Dwarnings"; \
		RUSTFLAGS="-D warnings" cargo check --all-targets; \
	fi

## audit: Check dependencies for known vulnerabilities
audit:
	cargo audit

## check: Build check + lint + audit (fast pre-commit validation)
check: lint audit
	cargo check

#---------------------------------------------------------------------------
# Release
#---------------------------------------------------------------------------

## fmt: Format all source files
fmt:
	cargo fmt

## release-check: Verify everything is ready for release
release-check: fmt lint test
	cargo doc --no-deps
	@echo "All checks passed — ready to release"

#---------------------------------------------------------------------------
# Help
#---------------------------------------------------------------------------

## help: Show this help
help:
	@echo "lessence Development Commands"
	@echo ""
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/ /'
