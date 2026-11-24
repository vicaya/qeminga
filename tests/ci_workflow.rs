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
use std::path::{Path, PathBuf};

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

/// The git environment for listing the files of `dir`: none when `dir` is
/// a checkout; otherwise (an unpacked source archive) a throwaway
/// repository, kept alive by the returned guard, whose work tree is `dir`.
fn git_inventory_env(dir: &Path) -> (Option<tempfile::TempDir>, Vec<(&'static str, PathBuf)>) {
    if dir.join(".git").exists() {
        return (None, Vec::new());
    }
    let meta = tempfile::tempdir().unwrap();
    let git_dir = meta.path().join("meta.git");
    let status = std::process::Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(&git_dir)
        .status()
        .expect("git is needed by this test");
    assert!(status.success(), "git init --bare");
    let env = vec![("GIT_DIR", git_dir), ("GIT_WORK_TREE", dir.to_owned())];
    (Some(meta), env)
}

/// Runs `scripts/check-shell.sh --list DIR` (no shellcheck is needed for
/// the listing) with `env` added to a git environment that never reaches
/// a repository enclosing `dir`.
fn check_shell_list(dir: &Path, env: &[(&str, PathBuf)]) -> std::process::Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-shell.sh");
    let mut cmd = std::process::Command::new(&script);
    cmd.arg("--list")
        .arg(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env("GIT_CEILING_DIRECTORIES", dir.parent().unwrap());
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("{}: {e}", script.display()))
}

/// The scripts `check_shell_list` reports, sorted, failing the test if
/// the listing fails.
fn linted_shell_scripts(dir: &Path, env: &[(&str, PathBuf)]) -> Vec<String> {
    let out = check_shell_list(dir, env);
    assert!(
        out.status.success(),
        "check-shell.sh --list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut listed: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    listed.sort();
    listed
}

/// Splits `text` into words as `env -S` does: whitespace separates, and
/// '...', "..." and backslash escapes are honoured. Nothing is expanded.
fn split_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => word.extend(chars.next()),
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_word = true;
            }
            (None, '\\') => {
                word.extend(chars.next());
                in_word = true;
            }
            (None, ' ' | '\t') => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            (None, c) => {
                word.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// The interpreter a `#!` line runs: its first word, or for `env` the
/// first word after env's options (a split string, `-S STRING`, `-SSTRING`
/// or `--split-string=STRING`, is split again) and `NAME=value`
/// assignments.
fn shebang_interpreter(line: &str) -> Option<String> {
    fn program(word: &str) -> String {
        word.rsplit('/').next().unwrap_or(word).to_owned()
    }
    let words = split_words(line.strip_prefix("#!")?);
    let first = words.first()?;
    if program(first) != "env" {
        return Some(program(first));
    }
    let mut args: std::collections::VecDeque<String> = words[1..].iter().cloned().collect();
    while let Some(word) = args.pop_front() {
        let split = word
            .strip_prefix("--split-string=")
            .or_else(|| word.strip_prefix("-S").filter(|rest| !rest.is_empty()));
        if let Some(split) = split {
            for (i, w) in split_words(split).into_iter().enumerate() {
                args.insert(i, w);
            }
            continue;
        }
        match word.as_str() {
            "-u" | "--unset" | "-C" | "--chdir" => {
                args.pop_front();
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
        shebang_interpreter(first.trim_end()).as_deref(),
        Some("sh" | "bash" | "dash")
    )
}

#[test]
fn shebang_interpreters_are_matched_as_words_with_their_arguments() {
    for (line, interpreter) in [
        ("#!/bin/sh", Some("sh")),
        ("#!/bin/bash -eu", Some("bash")),
        ("#! /bin/dash -e", Some("dash")),
        ("#!/usr/bin/env bash", Some("bash")),
        ("#!/usr/bin/env -S bash -eu", Some("bash")),
        ("#!/usr/bin/env -S 'bash' -eu", Some("bash")),
        ("#!/usr/bin/env -S\"/bin/sh\" -e", Some("sh")),
        ("#!/usr/bin/env -Sbash -e", Some("bash")),
        ("#!/usr/bin/env --split-string=bash -eu", Some("bash")),
        ("#!/usr/bin/env --split-string='dash -e'", Some("dash")),
        ("#!/usr/bin/env -S -u HOME LC_ALL=C sh -e", Some("sh")),
        ("#!/usr/bin/env -u HOME LC_ALL=C sh -e", Some("sh")),
        ("#!/usr/bin/bashful", Some("bashful")),
        ("#!/usr/bin/env python3", Some("python3")),
        ("#!/usr/bin/env -S 'python3 -u'", Some("python3 -u")),
        ("#!/usr/bin/env", None),
        ("# not a shebang", None),
    ] {
        assert_eq!(shebang_interpreter(line).as_deref(), interpreter, "{line}");
    }
}

/// The shell scripts among the files git lists for `dir` (tracked and
/// untracked, never ignored), classified here independently of the
/// script: regular files only, so links and the directories git reports
/// for embedded repositories and submodules are left out.
fn shell_scripts_in_inventory(dir: &Path, env: &[(&str, PathBuf)]) -> Vec<String> {
    let mut cmd = std::process::Command::new("git");
    cmd.current_dir(dir)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env("GIT_CEILING_DIRECTORIES", dir.parent().unwrap());
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("git is needed by this test");
    assert!(out.status.success(), "git ls-files");
    let mut found: Vec<String> = out
        .stdout
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8(p.to_vec()).unwrap())
        .filter(|p| {
            std::fs::symlink_metadata(dir.join(p)).is_ok_and(|m| m.is_file())
                && is_shell_script(&dir.join(p))
        })
        .collect();
    found.sort();
    found
}

#[test]
fn shellcheck_covers_every_shell_script_in_the_repository() {
    // From a checkout, git's own inventory; from an unpacked source
    // archive (no .git), the same inventory through a throwaway repository.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (_meta, env) = git_inventory_env(root);
    let linted = linted_shell_scripts(root, &env);
    assert_eq!(linted, shell_scripts_in_inventory(root, &env));
    assert!(
        linted.len() >= 11,
        "only {} shell scripts listed",
        linted.len()
    );
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
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .expect("git is needed by this test");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The fixture repository of the listing tests, and the scripts it holds.
fn fixture_repository(dir: &Path) -> Vec<&'static str> {
    git(dir, &["init", "-q"]);
    // Shell scripts, tracked and untracked, inside and outside scripts/.
    put(dir, "lib.sh", "echo no shebang, named .sh\n");
    put(dir, "-helper.sh", "echo a name that looks like an option\n");
    put(dir, "bash-eu", "#!/bin/bash -eu\necho\n");
    put(dir, "tools/dash-e", "#!/bin/dash -e\necho\n");
    put(dir, "tools/env-split", "#!/usr/bin/env -S bash -eu\necho\n");
    put(
        dir,
        "tools/env-split-long",
        "#!/usr/bin/env --split-string=bash -eu\necho\n",
    );
    put(
        dir,
        "tools/env-split-quoted",
        "#!/usr/bin/env -S 'bash' -eu\necho\n",
    );
    put(dir, "deep/er/plain", "#!/bin/sh\necho\n");
    put(dir, "untracked-env-sh", "#!/usr/bin/env sh\necho\n");
    // Not shell scripts.
    put(dir, "tool.py", "#!/usr/bin/env python3\nprint()\n");
    put(dir, "bashful", "#!/usr/bin/bashful\n");
    put(dir, "notes.txt", "run it with /bin/bash\n");
    std::fs::write(dir.join("blob"), [0u8, 0xff, b'\n', 0]).unwrap();
    // Ignored output (by .gitignore and by the repository-local excludes)
    // and links to linted scripts are not linted.
    put(dir, ".gitignore", "out/\ndebug\n");
    put(dir, "out/generated.sh", "#!/bin/sh\necho\n");
    put(dir, "debug/local-test.sh", "#!/bin/sh\necho\n");
    put(dir, ".git/info/exclude", "scratch.sh\n");
    put(dir, "scratch.sh", "#!/bin/sh\necho\n");
    std::os::unix::fs::symlink("bash-eu", dir.join("lint-alias")).unwrap();
    std::os::unix::fs::symlink("lib.sh", dir.join("alias.sh")).unwrap();
    // Embedded repositories are separate repositories: an untracked
    // nested checkout and a submodule (a gitlink) are not entered.
    put(dir, "checkout/in.sh", "#!/bin/sh\necho\n");
    git(&dir.join("checkout"), &["init", "-q"]);
    put(dir, "sub/in.sh", "#!/bin/sh\necho\n");
    git(&dir.join("sub"), &["init", "-q"]);
    git(&dir.join("sub"), &["add", "in.sh"]);
    git(&dir.join("sub"), &["commit", "-q", "-m", "sub"]);
    git(
        dir,
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
            "sub",
        ],
    );
    vec![
        "-helper.sh",
        "bash-eu",
        "deep/er/plain",
        "lib.sh",
        "tools/dash-e",
        "tools/env-split",
        "tools/env-split-long",
        "tools/env-split-quoted",
        "untracked-env-sh",
    ]
}

#[test]
fn the_listing_finds_scripts_by_name_and_interpreter_and_skips_links_ignored_files_and_embedded_repositories()
 {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("repo");
    std::fs::create_dir(&dir).unwrap();
    let expected = fixture_repository(&dir);
    assert_eq!(linted_shell_scripts(&dir, &[]), expected);
    // The independent classification of the coverage test agrees.
    assert_eq!(shell_scripts_in_inventory(&dir, &[]), expected);
}

#[test]
fn an_unpacked_source_archive_is_listed_through_a_throwaway_repository() {
    // `git archive` output has no .git: the coverage test must still run.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("archive");
    std::fs::create_dir(&dir).unwrap();
    put(&dir, ".gitignore", "target\n");
    put(&dir, "scripts/a.sh", "#!/bin/sh\necho\n");
    put(&dir, "target/b.sh", "#!/bin/sh\necho\n");
    let (meta, env) = git_inventory_env(&dir);
    assert!(meta.is_some());
    assert_eq!(linted_shell_scripts(&dir, &env), ["scripts/a.sh"]);
    assert_eq!(shell_scripts_in_inventory(&dir, &env), ["scripts/a.sh"]);
}

#[test]
fn a_listing_that_cannot_be_established_fails() {
    // Not a git work tree: the file list is unknown, never empty.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("plain");
    std::fs::create_dir(&dir).unwrap();
    put(&dir, "x.sh", "#!/bin/sh\necho\n");
    let out = check_shell_list(&dir, &[]);
    assert!(!out.status.success(), "listed {:?}", out.stdout);
    assert!(out.stdout.is_empty());
}

#[test]
fn the_linter_ignores_caller_configuration() {
    // AGENTS.md: a finding is silenced only by a directive at the command
    // it covers, so no .shellcheckrc (`--norc`) and no SHELLCHECK_OPTS may
    // apply, and a file name is never read as an option (`--`).
    let script = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-shell.sh"),
    )
    .unwrap();
    let lines: Vec<&str> = script.lines().map(str::trim).collect();
    let unset = lines
        .iter()
        .position(|l| *l == "unset SHELLCHECK_OPTS")
        .expect("check-shell.sh clears SHELLCHECK_OPTS");
    let runs: Vec<(usize, &&str)> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with("shellcheck ") && !l.starts_with("shellcheck --version"))
        .collect();
    assert!(!runs.is_empty(), "check-shell.sh never runs shellcheck");
    for (at, run) in runs {
        assert!(at > unset, "{run} runs before SHELLCHECK_OPTS is cleared");
        assert!(
            run.starts_with("shellcheck --norc -- "),
            "{run}: not `shellcheck --norc -- FILES`"
        );
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

/// The shellcheck release `scripts/check-shell.sh` is written against
/// (`SHELLCHECK_VERSION=` in the script).
fn pinned_shellcheck_version() -> String {
    let script = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-shell.sh"),
    )
    .unwrap();
    script
        .lines()
        .find_map(|l| l.strip_prefix("SHELLCHECK_VERSION="))
        .expect("check-shell.sh pins SHELLCHECK_VERSION")
        .to_owned()
}

#[test]
fn ci_installs_the_shellcheck_release_the_script_pins() {
    // Releases differ in what they report (0.11 added SC2329), so CI must
    // not judge with whatever the runner image happens to ship.
    let version = pinned_shellcheck_version();
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()),
        "SHELLCHECK_VERSION={version} is not an exact release"
    );
    let text = workflow();
    let block = job(&text, "shellcheck");
    assert!(
        block.contains("uses: taiki-e/install-action@v2")
            && block.contains(&format!("tool: shellcheck@{version}")),
        "the shellcheck job installs shellcheck {version} (checksum-verified)"
    );
}
