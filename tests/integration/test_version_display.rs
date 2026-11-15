#[test]
fn test_version_shows_lessence_name() {
    let output = crate::common::lessence()
        .arg("--version")
        .output()
        .expect("lessence binary should exist");

    assert!(
        output.status.success(),
        "lessence --version should execute successfully"
    );

    let version_output = String::from_utf8_lossy(&output.stdout);

    assert!(
        version_output.to_lowercase().contains("lessence"),
        "Version output should contain 'lessence', got: {version_output}"
    );

    assert!(
        !version_output.to_lowercase().contains("logfold"),
        "Version output should not contain 'logfold', got: {version_output}"
    );
}

#[test]
fn test_version_format() {
    let output = crate::common::lessence()
        .arg("--version")
        .output()
        .expect("lessence binary should exist");

    let version_output = String::from_utf8_lossy(&output.stdout);

    let version_regex = regex::Regex::new(r"\d+\.\d+\.\d+").unwrap();
    assert!(
        version_regex.is_match(&version_output),
        "Version should contain semantic version number, got: {version_output}"
    );
}

#[test]
fn test_version_short_flag() {
    let output = crate::common::lessence()
        .arg("-V")
        .output()
        .expect("lessence binary should exist");

    assert!(output.status.success(), "-V should succeed");
    let long = crate::common::lessence()
        .arg("--version")
        .output()
        .expect("lessence binary should exist");
    assert!(long.status.success(), "--version should succeed");
    assert!(!output.stdout.is_empty(), "-V should print the version");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&long.stdout),
        "-V must print what --version prints"
    );
}

#[test]
fn test_version_reports_build_identity() {
    let output = crate::common::lessence()
        .arg("--version")
        .output()
        .expect("lessence binary should exist");

    let version_output = String::from_utf8_lossy(&output.stdout);

    let shape = regex::Regex::new(r"^lessence \d+\.\d+\.\d+ \([^,()]+, [^,()]+\)\s*$").unwrap();
    assert!(
        shape.is_match(version_output.trim_end()),
        "semver alone does not identify a build, so --version reads `lessence X.Y.Z (<build-id>, <target>)` (the build id is `unknown` without git, so only the shape is checked), got: {version_output}"
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
