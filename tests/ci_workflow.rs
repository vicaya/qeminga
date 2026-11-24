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

/// Runs `scripts/ci/docs-only.sh` over `paths` and reports whether it
/// classified the change as documentation only.
fn docs_only(paths: &[&str]) -> bool {
    use std::io::Write;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci/docs-only.sh");
    let mut child = std::process::Command::new(&script)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{}: {e}", script.display()));
    let mut input = paths.join("\n");
    if !paths.is_empty() {
        input.push('\n');
    }
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap().status.success()
}

#[test]
fn markdown_no_check_reads_is_documentation_only() {
    assert!(docs_only(&[
        "README.md",
        "docs/tasks.md",
        "docs/testing.md",
        "CHANGELOG.md",
        "AGENTS.md",
    ]));
}

#[test]
fn markdown_a_test_parses_is_code() {
    // tests/packaging.rs reads design blocks and the packaging README.
    assert!(!docs_only(&["docs/design.md"]));
    assert!(!docs_only(&["README.md", "packaging/README.md"]));
}

#[test]
fn anything_else_and_an_empty_change_run_everything() {
    assert!(!docs_only(&["README.md", "src/lib.rs"]));
    assert!(!docs_only(&[".github/workflows/ci.yml"]));
    assert!(!docs_only(&["Cargo.lock"]));
    assert!(!docs_only(&["docs/notes.markdown"]));
    assert!(!docs_only(&[]));
}

#[test]
fn every_job_that_runs_cargo_waits_for_the_change_classification() {
    let text = workflow();
    let changes = job(&text, "changes");
    assert!(
        changes.contains("scripts/ci/docs-only.sh"),
        "the changes job classifies with the script the tests above cover"
    );
    let mut gated = 0;
    for line in text.lines() {
        if line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':') {
            let name = line.trim().trim_end_matches(':');
            let block = job(&text, name);
            if !block.contains("cargo ") {
                continue;
            }
            assert!(
                block.contains("needs: changes")
                    && block.contains("if: needs.changes.outputs.code == 'true'"),
                "{name}: runs cargo without waiting for the change classification"
            );
            gated += 1;
        }
    }
    assert!(gated >= 10, "only {gated} cargo jobs found");
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

/// Runs `scripts/check-shell.sh --list` over `dir` (the repository when
/// `None`); no shellcheck is needed for the listing.
fn check_shell_list(dir: Option<&Path>) -> std::process::Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-shell.sh");
    let mut cmd = std::process::Command::new(&script);
    cmd.arg("--list");
    if let Some(dir) = dir {
        // Never let git find the enclosing repository of a fixture.
        cmd.arg(dir)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env("GIT_CEILING_DIRECTORIES", dir.parent().unwrap());
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("{}: {e}", script.display()))
}

/// The scripts `check_shell_list` reports, failing the test if it fails.
fn linted_shell_scripts(dir: Option<&Path>) -> Vec<String> {
    let out = check_shell_list(dir);
    assert!(
        out.status.success(),
        "check-shell.sh --list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The interpreter a `#!` line runs: its first word, or for `env` the
/// first word after env's options and `NAME=value` assignments.
fn shebang_interpreter(line: &str) -> Option<&str> {
    fn program(word: &str) -> &str {
        word.rsplit('/').next().unwrap_or(word)
    }
    let mut words = line.strip_prefix("#!")?.split_whitespace();
    let first = words.next()?;
    if program(first) != "env" {
        return Some(program(first));
    }
    let mut words = words.peekable();
    while let Some(word) = words.next() {
        match word {
            "-u" | "--unset" | "-C" | "--chdir" => {
                words.next();
            }
            w if w.starts_with('-') || w.contains('=') => {}
            w => return Some(program(w)),
        }
    }
    None
}

/// Whether the file at `path` is a shell script by name (`*.sh`) or by the
/// interpreter its `#!` line names (sh, bash, dash). Only the start of the
/// file is read.
fn is_shell_script(path: &Path) -> bool {
    use std::io::{BufRead, Read};
    if path.extension().is_some_and(|e| e == "sh") {
        return true;
    }
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut first = Vec::new();
    std::io::BufReader::new(file.take(256))
        .read_until(b'\n', &mut first)
        .unwrap();
    let first = String::from_utf8_lossy(&first);
    matches!(
        shebang_interpreter(first.trim_end()),
        Some("sh" | "bash" | "dash")
    )
}

/// Build output and other generated trees that are git-ignored and that
/// `check-shell.sh` therefore never lints.
fn generated(name: &str) -> bool {
    matches!(name, ".git" | "target" | "artifacts" | "coverage") || name.starts_with("mutants.out")
}

/// Every regular file under `dir` (recursively, never following a
/// symbolic link: the source file is the unit of linting) that is a shell
/// script, relative to `root`.
fn shell_scripts_under(root: &Path, dir: &Path, found: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let path = entry.path();
        if kind.is_dir() {
            if !generated(&entry.file_name().to_string_lossy()) {
                shell_scripts_under(root, &path, found);
            }
        } else if kind.is_file() && is_shell_script(&path) {
            found.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
}

#[test]
fn shebang_interpreters_are_matched_as_words_with_their_arguments() {
    for (line, interpreter) in [
        ("#!/bin/sh", Some("sh")),
        ("#!/bin/bash -eu", Some("bash")),
        ("#! /bin/dash -e", Some("dash")),
        ("#!/usr/bin/env bash", Some("bash")),
        ("#!/usr/bin/env -S bash -eu", Some("bash")),
        ("#!/usr/bin/env -u HOME LC_ALL=C sh -e", Some("sh")),
        ("#!/usr/bin/bashful", Some("bashful")),
        ("#!/usr/bin/env python3", Some("python3")),
        ("#!/usr/bin/env", None),
        ("# not a shebang", None),
    ] {
        assert_eq!(shebang_interpreter(line), interpreter, "{line}");
    }
}

#[test]
fn shellcheck_covers_every_shell_script_in_the_repository() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut expected = Vec::new();
    shell_scripts_under(root, root, &mut expected);
    expected.sort();
    let linted = linted_shell_scripts(None);
    assert!(
        linted.len() >= 11,
        "only {} shell scripts listed",
        linted.len()
    );
    for script in &expected {
        assert!(
            linted.contains(script),
            "{script}: a shell script check-shell.sh does not lint"
        );
    }
    for must in ["scripts/check-unsafe.sh", "scripts/e2e-libvirt.sh"] {
        assert!(linted.iter().any(|s| s == must), "{must} is not linted");
    }
}

/// Writes `text` to `dir/rel`, creating its parent directories.
fn put(dir: &Path, rel: &str, text: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .status()
        .expect("git is needed by this test");
    assert!(status.success(), "git {args:?}");
}

#[test]
fn the_listing_finds_scripts_by_name_and_interpreter_and_skips_links_and_ignored_files() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("repo");
    std::fs::create_dir(&dir).unwrap();
    git(&dir, &["init", "-q"]);
    // Shell scripts, tracked and untracked, inside and outside scripts/.
    put(&dir, "lib.sh", "echo no shebang, named .sh\n");
    put(&dir, "bash-eu", "#!/bin/bash -eu\necho\n");
    put(&dir, "tools/dash-e", "#!/bin/dash -e\necho\n");
    put(
        &dir,
        "tools/env-split",
        "#!/usr/bin/env -S bash -eu\necho\n",
    );
    put(&dir, "deep/er/plain", "#!/bin/sh\necho\n");
    put(&dir, "untracked-env-sh", "#!/usr/bin/env sh\necho\n");
    // Not shell scripts.
    put(&dir, "tool.py", "#!/usr/bin/env python3\nprint()\n");
    put(&dir, "bashful", "#!/usr/bin/bashful\n");
    put(&dir, "notes.txt", "run it with /bin/bash\n");
    std::fs::write(dir.join("blob"), [0u8, 0xff, b'\n', 0]).unwrap();
    // Ignored output and a link to a linted script are not linted.
    put(&dir, ".gitignore", "out/\n");
    put(&dir, "out/generated.sh", "#!/bin/sh\necho\n");
    std::os::unix::fs::symlink("bash-eu", dir.join("lint-alias")).unwrap();
    std::os::unix::fs::symlink("lib.sh", dir.join("alias.sh")).unwrap();
    git(
        &dir,
        &[
            "add",
            ".gitignore",
            "lib.sh",
            "bash-eu",
            "tools",
            "deep",
            "tool.py",
            "lint-alias",
            "alias.sh",
        ],
    );
    assert_eq!(
        linted_shell_scripts(Some(&dir)),
        [
            "bash-eu",
            "deep/er/plain",
            "lib.sh",
            "tools/dash-e",
            "tools/env-split",
            "untracked-env-sh",
        ]
    );
}

#[test]
fn a_listing_that_cannot_be_established_fails() {
    // Not a git work tree: the file list is unknown, never empty.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("plain");
    std::fs::create_dir(&dir).unwrap();
    put(&dir, "x.sh", "#!/bin/sh\necho\n");
    let out = check_shell_list(Some(&dir));
    assert!(!out.status.success(), "listed {:?}", out.stdout);
    assert!(out.stdout.is_empty());
}

#[test]
fn the_linter_ignores_shellcheckrc_files() {
    // AGENTS.md: a finding is silenced only by a directive at the command
    // it covers, so no repository or per-user .shellcheckrc may apply.
    let script = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-shell.sh"),
    )
    .unwrap();
    let runs: Vec<&str> = script
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("shellcheck "))
        .collect();
    assert!(!runs.is_empty(), "check-shell.sh never runs shellcheck");
    for run in runs {
        assert!(run.starts_with("shellcheck --norc "), "{run}");
    }
}

#[test]
fn the_shellcheck_job_lints_every_script_and_cannot_fail_quietly() {
    let text = workflow();
    let block = job(&text, "shellcheck");
    assert!(
        block.contains("scripts/check-shell.sh"),
        "the shellcheck job runs the script the test above covers"
    );
    assert!(
        block.contains("shellcheck --version"),
        "the job records which shellcheck judged the scripts"
    );
    assert!(
        !block.contains("continue-on-error"),
        "a shellcheck finding must fail the workflow"
    );
}
