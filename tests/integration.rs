use std::path::PathBuf;
use std::process::Command;

fn quick_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_quick"))
}

fn sample(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn enum_from_json_decodes_payloads() {
    let output = Command::new(quick_bin())
        .args(["run", sample("tests/samples/enum_from_json.qx").to_str().unwrap()])
        .output()
        .expect("failed to run quick binary");

    assert!(
        output.status.success(),
        "quick run failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("beta:hi"), "expected enum payload in stdout, got {stdout:?}");
}

#[test]
fn io_write_returns_success_and_writes_file() {
    let target_file = sample("target/tmp_io_write.txt");
    let _ = std::fs::remove_file(&target_file);

    let output = Command::new(quick_bin())
        .args(["run", sample("tests/samples/io_write.qx").to_str().unwrap()])
        .output()
        .expect("failed to run quick binary");

    assert!(
        output.status.success(),
        "quick run failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let written = std::fs::read_to_string(&target_file)
        .expect("io.write did not create the expected output file");
    assert_eq!(written, "hello from quickscript");
}

#[test]
fn io_write_error_surfaces_message() {
    let output = Command::new(quick_bin())
        .args(["run", sample("tests/samples/io_write_error.qx").to_str().unwrap()])
        .output()
        .expect("failed to run quick binary");

    assert!(
        output.status.success(),
        "quick run failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("err:"),
        "expected an error prefix from io.write failure, got {stdout:?}"
    );
}

#[test]
fn range_builder_supports_positive_step() {
    let output = Command::new(quick_bin())
        .args(["run", sample("tests/samples/range_positive.qx").to_str().unwrap()])
        .output()
        .expect("failed to run quick binary");

    assert!(
        output.status.success(),
        "quick run failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<f64> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.parse::<f64>().expect("range output should be numeric"))
        .collect();
    assert_eq!(lines, vec![1.0, 3.0], "unexpected positive-step range output");
}

#[test]
fn range_builder_supports_negative_step() {
    let output = Command::new(quick_bin())
        .args(["run", sample("tests/samples/range_negative.qx").to_str().unwrap()])
        .output()
        .expect("failed to run quick binary");

    assert!(
        output.status.success(),
        "quick run failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<f64> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.parse::<f64>().expect("range output should be numeric"))
        .collect();
    assert_eq!(lines, vec![5.0, 3.0, 1.0], "unexpected negative-step range output");
}
