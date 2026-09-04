//! `scripts/ci/coverage-gate.py` (T5.7): the floor applies to production
//! lines only, so the inline `#[cfg(test)] mod tests` block of each file is
//! removed from the LCOV before the percentage is computed.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

const SOURCE: &str = "pub fn a() -> u32 {\n    1\n}\n\npub fn b() -> u32 {\n    2\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(super::a(), 1);\n    }\n}\n";

fn run(lcov: &str, source: &str, floor: &str) -> (i32, String, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/m.rs"), source).unwrap();
    std::fs::write(dir.path().join("cov.info"), lcov).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci/coverage-gate.py");
    let out = Command::new("python3")
        .arg(script)
        .arg("cov.info")
        .args([
            "--floor",
            floor,
            "--json",
            "s.json",
            "--filtered",
            "prod.info",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let json = std::fs::read_to_string(dir.path().join("s.json")).unwrap_or_default();
    let filtered = std::fs::read_to_string(dir.path().join("prod.info")).unwrap_or_default();
    (
        out.status.code().unwrap(),
        format!(
            "{}{}\n{json}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        filtered,
    )
}

// Production lines 1, 2, 5, 6 (a covered, b not); test lines 11-14 covered.
const LCOV: &str = "SF:src/m.rs\nDA:1,1\nDA:2,1\nDA:5,0\nDA:6,0\nDA:11,1\nDA:12,1\nDA:13,1\nDA:14,1\nLF:8\nLH:6\nend_of_record\n";

#[test]
fn inline_test_lines_are_excluded_from_the_production_figure() {
    let (code, text, filtered) = run(LCOV, SOURCE, "40");
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains(
            "\"production_lines\": {\n    \"found\": 4,\n    \"hit\": 2,\n    \"percent\": 50.0"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "\"all_lines\": {\n    \"found\": 8,\n    \"hit\": 6,\n    \"percent\": 75.0"
        ),
        "{text}"
    );
    assert!(!filtered.contains("DA:11,"), "{filtered}");
    assert!(filtered.contains("DA:5,0"), "{filtered}");
    assert!(filtered.contains("LF:4\nLH:2"), "{filtered}");
}

#[test]
fn the_floor_applies_to_production_lines_not_all_lines() {
    // All lines are at 75 %, production at 50 %: a 60 % floor fails.
    let (code, text, _) = run(LCOV, SOURCE, "60");
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("below the floor 60%"), "{text}");
    assert!(text.contains("\"passed\": false"), "{text}");
}

#[test]
fn a_file_without_inline_tests_is_counted_whole() {
    let source = "pub fn a() -> u32 {\n    1\n}\n";
    let lcov = "SF:src/m.rs\nDA:1,1\nDA:2,1\nend_of_record\n";
    let (code, text, _) = run(lcov, source, "100");
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("\"percent\": 100.0"), "{text}");
}

#[test]
fn production_code_after_the_test_module_is_rejected() {
    let source = format!("{SOURCE}\npub fn c() {{}}\n");
    let (code, text, _) = run(LCOV, &source, "0");
    assert_eq!(code, 2, "{text}");
    assert!(
        text.contains("top-level code after the inline test module"),
        "{text}"
    );
}

// Function records: `FNDA:<count>,<name>` carries an execution count, not a
// line, so it cannot be filtered by line; the filtered file is a line and
// branch report and carries no function records at all.
const LCOV_WITH_FUNCTIONS: &str = "SF:src/m.rs\nFN:1,a\nFN:5,b\nFN:11,tests::t\nFNDA:500,a\nFNDA:0,b\nFNDA:1,tests::t\nFNF:3\nFNH:2\nDA:1,500\nDA:2,500\nDA:5,0\nDA:6,0\nDA:11,1\nDA:12,1\nDA:13,1\nDA:14,1\nBRDA:2,0,0,500\nBRDA:12,0,0,1\nBRF:2\nBRH:2\nLF:8\nLH:6\nend_of_record\n";

#[test]
fn function_records_are_not_filtered_by_their_execution_count() {
    let (code, text, filtered) = run(LCOV_WITH_FUNCTIONS, SOURCE, "40");
    assert_eq!(code, 0, "{text}");
    for record in ["FN:", "FNDA:", "FNF:", "FNH:", "FNL:", "FNA:"] {
        assert!(
            !filtered.contains(record),
            "{record} must not survive into the line report:\n{filtered}"
        );
    }
    // Branch records do carry a line and follow the same cut as DA.
    assert!(filtered.contains("BRDA:2,0,0,500"), "{filtered}");
    assert!(!filtered.contains("BRDA:12,"), "{filtered}");
    assert!(text.contains("\"percent\": 50.0"), "{text}");
}

#[test]
fn excluded_test_support_files_do_not_count_as_production() {
    // Two files: the production module and a test double compiled
    // unconditionally. The double is fully covered and would lift the
    // production figure; `--exclude` removes it from that figure and from
    // the filtered report while the all-lines figure still counts it.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src/kernel")).unwrap();
    std::fs::write(dir.path().join("src/m.rs"), SOURCE).unwrap();
    std::fs::write(
        dir.path().join("src/kernel/fake.rs"),
        "pub fn f() -> u32 {\n    3\n}\n",
    )
    .unwrap();
    let lcov = format!("{LCOV}SF:src/kernel/fake.rs\nDA:1,1\nDA:2,1\nend_of_record\n");
    std::fs::write(dir.path().join("cov.info"), lcov).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci/coverage-gate.py");
    let out = Command::new("python3")
        .arg(script)
        .args([
            "cov.info",
            "--floor",
            "55",
            "--exclude",
            "src/kernel/fake.rs",
            "--json",
            "s.json",
            "--filtered",
            "prod.info",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let text = format!(
        "{}{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        std::fs::read_to_string(dir.path().join("s.json")).unwrap_or_default()
    );
    // With the double counted the production figure would be 4/6 = 66.7 %
    // and pass a 55 % floor; without it, 2/4 = 50 % fails.
    assert_eq!(out.status.code().unwrap(), 1, "{text}");
    assert!(
        text.contains("\"found\": 4,\n    \"hit\": 2,\n    \"percent\": 50.0"),
        "{text}"
    );
    assert!(
        text.contains("\"found\": 10,\n    \"hit\": 8,\n    \"percent\": 80.0"),
        "{text}"
    );
    assert!(
        text.contains("\"excluded\": [\n    \"src/kernel/fake.rs\"\n  ]"),
        "{text}"
    );
    let filtered = std::fs::read_to_string(dir.path().join("prod.info")).unwrap();
    assert!(!filtered.contains("SF:src/kernel/fake.rs"), "{filtered}");
    assert!(filtered.contains("SF:src/m.rs"), "{filtered}");
}
