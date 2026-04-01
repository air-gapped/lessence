use std::process::Command;

#[test]
fn test_build_produces_zero_warnings() {
    let output = Command::new("cargo")
        .args(&["build", "--all-targets"])
        .output()
        .expect("Failed to execute cargo build");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    let warning_count = stderr.lines()
        .filter(|line| line.contains("warning:"))
        .count();
    
    assert_eq!(
        warning_count, 0,
        "Build produced {} warnings:\n{}",
        warning_count, stderr
    );
    
    assert!(
        output.status.success(),
        "Build failed with exit code: {:?}",
        output.status.code()
    );
}

#[test]
fn test_clippy_produces_zero_warnings() {
    let output = Command::new("cargo")
        .args(&["clippy", "--all-targets", "--", "-D", "warnings"])
        .output()
        .expect("Failed to execute cargo clippy");
    
    assert!(
        output.status.success(),
        "Clippy found issues:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
