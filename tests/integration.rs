use std::path::PathBuf;
use std::process::{Command, Output};

fn quick_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_quick"))
}

fn sample(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn run_sample_raw(path: &str) -> Output {
    Command::new(quick_bin())
        .args(["run", sample(path).to_str().unwrap()])
        .output()
        .expect("failed to run quick binary")
}

fn run_sample_ok(path: &str) -> String {
    let output = run_sample_raw(path);
    assert!(
        output.status.success(),
        "quick run failed for {path}: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_sample_err(path: &str) -> (Output, String, String) {
    let output = run_sample_raw(path);
    assert!(
        !output.status.success(),
        "expected quick run to fail for {path}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output, stdout, stderr)
}

fn non_empty_lines(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

#[test]
fn enum_from_json_decodes_payloads() {
    let stdout = run_sample_ok("tests/samples/enum_from_json.qx");
    assert!(
        stdout.contains("beta:hi"),
        "expected enum payload in stdout, got {stdout:?}"
    );
}

#[test]
fn io_write_returns_success_and_writes_file() {
    let target_file = sample("target/tmp_io_write.txt");
    let _ = std::fs::remove_file(&target_file);

    let _ = run_sample_ok("tests/samples/io_write.qx");

    let written = std::fs::read_to_string(&target_file)
        .expect("io.write did not create the expected output file");
    assert_eq!(written, "hello from quickscript");
}

#[test]
fn io_write_error_surfaces_message() {
    let stdout = run_sample_ok("tests/samples/io_write_error.qx");
    assert!(
        stdout.contains("err:"),
        "expected an error prefix from io.write failure, got {stdout:?}"
    );
}

#[test]
fn range_builder_supports_positive_step() {
    let stdout = run_sample_ok("tests/samples/range_positive.qx");
    let lines: Vec<f64> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.parse::<f64>().expect("range output should be numeric"))
        .collect();
    assert_eq!(
        lines,
        vec![1.0, 3.0],
        "unexpected positive-step range output"
    );
}

#[test]
fn range_builder_supports_negative_step() {
    let stdout = run_sample_ok("tests/samples/range_negative.qx");
    let lines: Vec<f64> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.parse::<f64>().expect("range output should be numeric"))
        .collect();
    assert_eq!(
        lines,
        vec![5.0, 3.0, 1.0],
        "unexpected negative-step range output"
    );
}

#[test]
fn basics_cover_math_strings_collections_io() {
    let stdout = run_sample_ok("tests/samples/basics.qx");
    let lines = non_empty_lines(&stdout);
    let mut iter = lines.iter();
    let expected_prefixes = vec![
        "add:3.000000",
        "mul:12.000000",
        "div:4.000000",
        "sub:7.000000",
        "cmp:true",
        "eq:true",
        "and:false",
        "or:true",
        "strlen:9.000000",
        "starts:true",
        "ends:true",
        "contains:true",
        "replace:heXXo.txt",
        "splitlen:3.000000",
        "splitmid:b",
        "join:a-b-c",
        "num:42.000000",
        "index:o",
    ];
    for expected in expected_prefixes {
        assert_eq!(
            iter.next(),
            Some(&expected.to_string()),
            "missing or out-of-order output near {expected}"
        );
    }

    let random_line = iter.next().expect("missing random output");
    assert!(
        random_line.starts_with("random:"),
        "random output should be prefixed, got {random_line}"
    );
    let _rand_value: f64 = random_line["random:".len()..]
        .parse()
        .expect("random output should be numeric");

    let remaining: Vec<&str> = iter.map(|s| s.as_str()).collect();
    let expected_tail = vec![
        "range:2.000000",
        "range:4.000000",
        "range:6.000000",
        "while:3.000000",
        "listlen:2.000000",
        "listidx:4.000000",
        "listafter:2.000000",
        "read:read contents",
    ];
    assert_eq!(
        remaining, expected_tail,
        "unexpected tail output from basics sample"
    );
}

#[test]
fn options_and_results_cover_all_helpers() {
    let stdout = run_sample_ok("tests/samples/option_result.qx");
    let lines = non_empty_lines(&stdout);
    let expected = vec![
        "opt:is_some",
        "opt:match_some:nine",
        "opt:is_none",
        "res:is_ok:enum Mode { Alpha, Beta(Str), }",
        "res:is_err",
    ];
    assert_eq!(lines, expected, "option/result output mismatch");
}

#[test]
fn objects_enums_modules_and_closures_work_together() {
    let stdout = run_sample_ok("tests/samples/objects_enums_modules.qx");
    let lines = non_empty_lines(&stdout);
    let expected = vec![
        "box:5.000000:hi",
        "box_from_json:json",
        "pair_sum:3.000000",
        "mood:sad:wow",
        "obj:a:one",
        "obj:missing",
        "module:Hello, World!",
        "module_const:67.000000",
    ];
    assert_eq!(lines, expected, "object/enum/module output mismatch");
}

#[test]
fn json_builtins_cover_all_accessors() {
    let stdout = run_sample_ok("tests/samples/json_builtins.qx");
    let lines = non_empty_lines(&stdout);
    let expected = vec![
        "json:name:quick",
        "json:first:1",
        "json:null:true",
        "json:missing",
    ];
    assert_eq!(lines, expected, "json builtins output mismatch");
}

#[test]
fn for_loops_reject_non_range_iterators() {
    let (_out, _stdout, stderr) = run_sample_err("tests/samples/for_over_list_error.qx");
    assert!(
        stderr.contains("io.range"),
        "expected range-only for loop error, got stderr={stderr:?}"
    );
}

#[test]
fn list_join_requires_string_lists() {
    let (_out, _stdout, stderr) = run_sample_err("tests/samples/list_join_error.qx");
    assert!(
        stderr.contains("list of strings"),
        "expected join type error, got stderr={stderr:?}"
    );
}
