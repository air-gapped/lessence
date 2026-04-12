// Build validation: ensure the project compiles successfully.
// Clippy enforcement is handled by `make ci` (cargo clippy --all-targets -D warnings),
// not by running clippy inside a test binary.

use std::process::Command;

#[test]
fn test_build_succeeds() {
    let output = Command::new("cargo")
        .args(["build", "--all-targets"])
        .output()
        .expect("Failed to execute cargo build");

    assert!(
        output.status.success(),
        "Build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
