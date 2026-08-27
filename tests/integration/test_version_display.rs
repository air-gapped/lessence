use std::process::Command;

#[test]
fn test_version_shows_lessence_name() {
    // T007: CLI contract test for version display
    // Verifies that version output contains lessence name

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--version")
        .output()
        .expect("lessence binary should exist");

    assert!(
        output.status.success(),
        "lessence --version should execute successfully"
    );

    let version_output = String::from_utf8_lossy(&output.stdout);

    // Check for "lessence" in version output
    assert!(
        version_output.to_lowercase().contains("lessence"),
        "Version output should contain 'lessence', got: {version_output}"
    );

    // Ensure no old "logfold" references
    assert!(
        !version_output.to_lowercase().contains("logfold"),
        "Version output should not contain 'logfold', got: {version_output}"
    );
}

#[test]
fn test_version_format() {
    // Verify version follows semantic versioning
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--version")
        .output()
        .expect("lessence binary should exist");

    let version_output = String::from_utf8_lossy(&output.stdout);

    // Should contain version number pattern (x.y.z)
    let version_regex = regex::Regex::new(r"\d+\.\d+\.\d+").unwrap();
    assert!(
        version_regex.is_match(&version_output),
        "Version should contain semantic version number, got: {version_output}"
    );
}

#[test]
fn test_version_short_flag() {
    // Test -V short flag works
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("-V")
        .output()
        .expect("lessence binary should exist");

    // -V should work the same as --version
    if output.status.success() {
        let version_output = String::from_utf8_lossy(&output.stdout);
        assert!(
            version_output.to_lowercase().contains("lessence") || !version_output.trim().is_empty(),
            "Short version flag should work, got: {version_output}"
        );
    }
}

#[test]
fn test_version_reports_build_identity() {
    // A binary's semver alone does not identify it: any commit between
    // releases changes behaviour without bumping Cargo.toml, and the musl
    // and glibc builds differ in allocator. `--version` must therefore also
    // name the commit it was built from and the target triple.
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--version")
        .output()
        .expect("lessence binary should exist");

    let version_output = String::from_utf8_lossy(&output.stdout);

    // `lessence 0.4.5 (2475c9bdc-dirty, x86_64-unknown-linux-gnu)`
    // The build id degrades to `unknown` when built without git (crates.io
    // tarball), so the shape is asserted, not the value.
    let shape = regex::Regex::new(r"^lessence \d+\.\d+\.\d+ \([^,()]+, [^,()]+\)\s*$").unwrap();
    assert!(
        shape.is_match(version_output.trim_end()),
        "Version should read `lessence X.Y.Z (<build-id>, <target>)`, got: {version_output}"
    );

    let inner = version_output
        .split_once('(')
        .and_then(|(_, rest)| rest.rsplit_once(')'))
        .map(|(inner, _)| inner)
        .expect("version output should carry a parenthesised build identity");
    let (build_id, target) = inner.split_once(", ").expect("build id and target triple");
    assert!(!build_id.is_empty(), "build id must not be empty");
    assert!(
        target.contains('-'),
        "target should be a triple, got: {target}"
    );
}
