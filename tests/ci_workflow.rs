//! The CI workflow runs the ordinary and the privileged suites natively on
//! both supported architectures (design §8.5, D6, AC15; #51). A change
//! that dropped an architecture from a matrix, moved the arm64 leg onto an
//! x86-64 runner, skipped the proof that a leg really is native, or let an
//! arm64 leg fail without failing the workflow is caught here before it
//! could pass on GitHub. Text-level checks: the workflow keeps each
//! architecture entry on one line for that reason.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

/// The jobs that must run natively on every supported architecture.
const NATIVE_JOBS: [&str; 2] = ["test", "privileged"];

/// Architecture name (`uname -m`) to the GitHub-hosted runner that
/// executes it natively.
const RUNNERS: [(&str, &str); 2] = [("x86_64", "ubuntu-24.04"), ("aarch64", "ubuntu-24.04-arm")];

fn workflow() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The text of one job: from its key (two-space indent under `jobs:`) to
/// the next key at that indent.
fn job<'a>(text: &'a str, name: &str) -> &'a str {
    let key = format!("\n  {name}:\n");
    let start = text.find(&key).unwrap_or_else(|| panic!("no job {name}")) + 1;
    let body = &text[start + key.len() - 1..];
    let end = body
        .lines()
        .scan(0, |offset, line| {
            let at = *offset;
            *offset += line.len() + 1;
            Some((at, line))
        })
        .find(|(_, line)| {
            line.starts_with("  ")
                && !line.starts_with("   ")
                && line.trim_end().ends_with(':')
                && !line.trim_start().starts_with('#')
        })
        .map_or(body.len(), |(at, _)| at);
    &text[start..start + key.len() - 1 + end]
}

/// The one-line flow mappings of the job's architecture matrix
/// (`- { name: aarch64, runner: ubuntu-24.04-arm, ... }`), keyed by name.
fn arch_matrix(job: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    job.lines()
        .map(str::trim)
        .filter(|line| line.starts_with("- {") && line.contains("runner:"))
        .map(|line| {
            let inner = line.trim_start_matches("- {").trim_end_matches('}').trim();
            let fields: BTreeMap<String, String> = inner
                .split(',')
                .map(|field| {
                    let (k, v) = field.split_once(':').expect(field);
                    (k.trim().to_owned(), v.trim().to_owned())
                })
                .collect();
            (fields["name"].clone(), fields)
        })
        .collect()
}

#[test]
fn the_test_and_privileged_jobs_run_natively_on_both_architectures() {
    let text = workflow();
    for name in NATIVE_JOBS {
        let job = job(&text, name);
        assert!(
            job.contains("runs-on: ${{ matrix.arch.runner }}"),
            "{name}: the runner must come from the architecture matrix"
        );
        let matrix = arch_matrix(job);
        let seen: Vec<(&str, &str)> = matrix
            .iter()
            .map(|(arch, fields)| (arch.as_str(), fields["runner"].as_str()))
            .collect();
        let mut expected = RUNNERS.to_vec();
        expected.sort_unstable();
        assert_eq!(seen, expected, "{name}: architecture matrix");
    }
}

#[test]
fn every_native_leg_proves_its_architecture_before_running_anything() {
    let text = workflow();
    for name in NATIVE_JOBS {
        let job = job(&text, name);
        let proof = job
            .find(r#"test "$(uname -m)" = "${{ matrix.arch.name }}""#)
            .unwrap_or_else(|| panic!("{name}: no uname -m assertion"));
        assert!(
            job.contains(r#"grep -qx "host: ${{ matrix.arch.name }}-unknown-linux-gnu""#),
            "{name}: the Rust host triple must be asserted too"
        );
        let first_cargo = job.find("cargo ").unwrap();
        assert!(
            proof < first_cargo,
            "{name}: the architecture is proved before the first cargo command"
        );
    }
}

#[test]
fn the_privileged_matrix_enforces_the_production_filter_on_every_architecture() {
    let text = workflow();
    let job = job(&text, "privileged");
    assert!(
        job.contains("ENFORCED_FEATURES: seccomp,suspend_ram,test-fakes"),
        "the enforced run names its features"
    );
    let all_features = job
        .lines()
        .filter(|line| line.contains("cargo ") && line.contains("--all-features"))
        .count();
    assert_eq!(
        all_features, 0,
        "--all-features would enable seccomp-log and stop testing enforcement"
    );
}

#[test]
fn no_native_job_is_allowed_to_fail_quietly() {
    let text = workflow();
    for name in NATIVE_JOBS {
        assert!(
            !job(&text, name).contains("continue-on-error"),
            "{name}: an architecture that may fail is not covered"
        );
    }
}
