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
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
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
        "docs/tasks.md",
        "docs/testing.md",
        "CHANGELOG.md",
        "AGENTS.md",
    ]));
}

#[test]
fn markdown_a_test_parses_is_code() {
    // tests/packaging.rs reads design blocks, the packaging README, and README.md.
    assert!(!docs_only(&["README.md"]));
    assert!(!docs_only(&["docs/design.md"]));
    assert!(!docs_only(&["docs/tasks.md", "packaging/README.md"]));
}

#[test]
fn anything_else_and_an_empty_change_run_everything() {
    assert!(!docs_only(&["docs/tasks.md", "src/lib.rs"]));
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

/// git's repository-local environment variables (`GIT_INDEX_FILE`,
/// `GIT_DIR`, `GIT_COMMON_DIR`, ...), as git itself names them.
fn git_local_env_vars() -> &'static [String] {
    static VARS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    VARS.get_or_init(|| {
        let out = std::process::Command::new("git")
            .args(["rev-parse", "--local-env-vars"])
            .output()
            .expect("git is needed by this test");
        assert!(out.status.success(), "git rev-parse --local-env-vars");
        let vars: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert!(vars.iter().any(|v| v == "GIT_INDEX_FILE"), "{vars:?}");
        vars
    })
}

/// Nothing of the caller's repository or configuration reaches a git
/// command of these tests: every repository-local variable a hook or
/// another git tool may have left set is cleared (an inherited
/// `GIT_INDEX_FILE` would make a fixture's `git add` rewrite the caller's
/// index), the global and system configuration and the per-user excludes
/// file are not read. A test's own overrides are set after this.
fn isolate_git(cmd: &mut std::process::Command) {
    for var in git_local_env_vars() {
        cmd.env_remove(var);
    }
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        // The default per-user excludes file ($XDG_CONFIG_HOME/git/ignore or
        // ~/.config/git/ignore) is read even without a global config.
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.excludesFile")
        .env("GIT_CONFIG_VALUE_0", "/dev/null");
}

/// The git environment for listing the files of `root`: none when it is
/// a checkout; otherwise (an unpacked source archive) a throwaway
/// repository, kept alive by the returned guard, whose work tree is `root`.
fn git_inventory_env(root: &Path) -> (Option<tempfile::TempDir>, Vec<(&'static str, PathBuf)>) {
    if root.join(".git").exists() {
        return (None, Vec::new());
    }
    let meta = tempfile::tempdir().unwrap();
    let git_dir = meta.path().join("meta.git");
    let mut init = std::process::Command::new("git");
    isolate_git(&mut init);
    let status = init
        .args(["init", "-q", "--bare"])
        .arg(&git_dir)
        .status()
        .expect("git is needed by this test");
    assert!(status.success(), "git init --bare");
    let env = vec![("GIT_DIR", git_dir), ("GIT_WORK_TREE", root.to_owned())];
    (Some(meta), env)
}

/// Where git looks for a repository: from `dir` up to the work tree
/// `root`, never into a repository enclosing `root` or the caller's (see
/// `isolate_git`), plus `env`.
fn git_env(cmd: &mut std::process::Command, root: &Path, env: &[(&str, PathBuf)]) {
    isolate_git(cmd);
    cmd.env("GIT_CEILING_DIRECTORIES", root.parent().unwrap());
    for (key, value) in env {
        cmd.env(key, value);
    }
}

/// Runs `scripts/check-shell.sh MODE DIR` (no shellcheck is needed for a
/// listing) for `dir` inside the work tree `root`.
fn check_shell(
    mode: &str,
    dir: &Path,
    root: &Path,
    env: &[(&str, PathBuf)],
) -> std::process::Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-shell.sh");
    let mut cmd = std::process::Command::new(&script);
    cmd.arg(mode).arg(dir);
    git_env(&mut cmd, root, env);
    cmd.output()
        .unwrap_or_else(|e| panic!("{}: {e}", script.display()))
}

/// Splits NUL-terminated paths, as raw bytes, sorted and unique.
fn nul_paths(bytes: &[u8]) -> Vec<OsString> {
    let mut paths: Vec<OsString> = bytes
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| OsStr::from_bytes(p).to_owned())
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// The scripts `check-shell.sh --list0` reports for `dir` (inside the work
/// tree `root`), exactly as emitted: the test fails if the listing fails,
/// or if a record is unterminated, repeated or out of byte order.
fn linted_shell_scripts(dir: &Path, root: &Path, env: &[(&str, PathBuf)]) -> Vec<OsString> {
    let out = check_shell("--list0", dir, root, env);
    assert!(
        out.status.success(),
        "check-shell.sh --list0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty() || out.stdout.ends_with(&[0]),
        "unterminated record: {:?}",
        out.stdout
    );
    let records: Vec<OsString> = out.stdout[..out.stdout.len().saturating_sub(1)]
        .split(|&b| b == 0)
        .filter(|_| !out.stdout.is_empty())
        .map(|p| OsStr::from_bytes(p).to_owned())
        .collect();
    assert!(
        records.windows(2).all(|w| w[0] < w[1]),
        "records repeated or out of order: {records:?}"
    );
    records
}

/// `paths` as `OsString`s, for comparisons.
fn os(paths: &[&str]) -> Vec<OsString> {
    paths.iter().map(OsString::from).collect()
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

/// The shell scripts among the files git lists for `dir` inside the work
/// tree `root` (tracked and untracked, never ignored; each path once, even
/// with several index stages during a merge), classified here
/// independently of the script: regular files only, so links and the
/// directories git reports for embedded repositories and submodules are
/// left out. Paths are kept as raw bytes.
fn shell_scripts_in_inventory(dir: &Path, root: &Path, env: &[(&str, PathBuf)]) -> Vec<OsString> {
    let mut cmd = std::process::Command::new("git");
    cmd.current_dir(dir).args([
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ]);
    git_env(&mut cmd, root, env);
    let out = cmd.output().expect("git is needed by this test");
    assert!(out.status.success(), "git ls-files");
    nul_paths(&out.stdout)
        .into_iter()
        .filter(|p| {
            let path = dir.join(p);
            std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) && is_shell_script(&path)
        })
        .collect()
}

#[test]
fn shellcheck_covers_every_shell_script_in_the_repository() {
    // From a checkout, git's own inventory; from an unpacked source
    // archive (no .git), the same inventory through a throwaway repository.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (_meta, env) = git_inventory_env(root);
    let linted = linted_shell_scripts(root, root, &env);
    assert_eq!(linted, shell_scripts_in_inventory(root, root, &env));
    assert!(
        linted.len() >= 11,
        "only {} shell scripts listed",
        linted.len()
    );
    for must in ["scripts/check-unsafe.sh", "scripts/e2e-libvirt.sh"] {
        assert!(
            linted.contains(&OsString::from(must)),
            "{must} is not linted"
        );
    }
}

#[test]
fn the_shell_fixtures_are_discovered_by_name_and_interpreter() {
    // tests/fixtures/shell is linted with the repository, so CI's pinned
    // shellcheck runs every listed fixture end to end; the others are not
    // valid shell and would fail it if they were listed.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("tests/fixtures/shell");
    let (_meta, env) = git_inventory_env(root);
    let expected = os(&[
        "bash-args",
        "dash-args",
        "directive-wins",
        "env-assign",
        "env-bash",
        "env-split",
        "env-split-attached",
        "env-split-long",
        "env-split-quoted",
        "heredoc-directive",
        "library.sh",
        "plain-sh",
    ]);
    assert_eq!(linted_shell_scripts(&dir, root, &env), expected);
    assert_eq!(shell_scripts_in_inventory(&dir, root, &env), expected);
}

/// Writes `bytes` to `dir/rel`, creating its parent directories.
fn put_bytes(dir: &Path, rel: &[u8], bytes: &[u8]) {
    let path = dir.join(OsStr::from_bytes(rel));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Writes `text` to `dir/rel`, creating its parent directories.
fn put(dir: &Path, rel: &str, text: &str) {
    put_bytes(dir, rel.as_bytes(), text.as_bytes());
}

/// `git -C dir` with a fixture identity, as variables a caller (a hook,
/// another git tool) left set as `inherited` would reach it.
fn git_command(dir: &Path, inherited: &[(&str, &Path)]) -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    for (key, value) in inherited {
        cmd.env(key, value);
    }
    isolate_git(&mut cmd);
    cmd.arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"]);
    cmd
}

/// Runs a fixture git command in `dir`, with `inherited` as in
/// `git_command`.
fn git_output_with(dir: &Path, args: &[&str], inherited: &[(&str, &Path)]) -> std::process::Output {
    if args.first() != Some(&"init") {
        // Before anything is written: the index is `dir`'s own.
        let out = git_command(dir, inherited)
            .args(["rev-parse", "--path-format=absolute", "--git-path", "index"])
            .output()
            .expect("git is needed by this test");
        assert!(out.status.success(), "git rev-parse in {}", dir.display());
        let index = PathBuf::from(OsStr::from_bytes(out.stdout.trim_ascii_end()));
        assert_eq!(
            index,
            dir.canonicalize().unwrap().join(".git/index"),
            "a fixture git command would use an index outside {}",
            dir.display()
        );
    }
    git_command(dir, inherited)
        .args(args)
        .output()
        .expect("git is needed by this test")
}

fn git_output(dir: &Path, args: &[&str]) -> std::process::Output {
    git_output_with(dir, args, &[])
}

fn git_with(dir: &Path, args: &[&str], inherited: &[(&str, &Path)]) {
    let out = git_output_with(dir, args, inherited);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn git(dir: &Path, args: &[&str]) {
    git_with(dir, args, &[]);
}

#[test]
fn fixture_git_ignores_the_callers_personal_excludes() {
    // GIT_CONFIG_GLOBAL=/dev/null alone still leaves git reading the
    // default per-user excludes file, $XDG_CONFIG_HOME/git/ignore.
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    put(&xdg, "git/ignore", "tools/\n*.sh\n");
    let inherited: [(&str, &Path); 1] = [("XDG_CONFIG_HOME", &xdg)];
    let fixture = tmp.path().join("fixture");
    std::fs::create_dir(&fixture).unwrap();
    git_with(&fixture, &["init", "-q"], &inherited);
    put(&fixture, "tools/a.sh", "#!/bin/sh\necho\n");
    put(&fixture, "b.sh", "#!/bin/sh\necho\n");
    git_with(&fixture, &["add", "tools"], &inherited);
    let untracked = git_output_with(
        &fixture,
        &["ls-files", "--others", "--exclude-standard"],
        &inherited,
    )
    .stdout;
    assert_eq!(untracked, b"b.sh\n");
}

#[test]
fn fixture_git_writes_never_reach_a_callers_repository() {
    // A caller with a staged change, and the repository-local variables a
    // hook or another git tool would leave set, pointing at it.
    let tmp = tempfile::tempdir().unwrap();
    let caller = tmp.path().join("caller");
    std::fs::create_dir(&caller).unwrap();
    git(&caller, &["init", "-q"]);
    put(&caller, "staged.txt", "keep\n");
    git(&caller, &["add", "staged.txt"]);
    let index = caller.join(".git/index");
    let before = std::fs::read(&index).unwrap();
    let git_dir = caller.join(".git");
    let leaked: [(&str, &Path); 3] = [
        ("GIT_INDEX_FILE", &index),
        ("GIT_DIR", &git_dir),
        ("GIT_COMMON_DIR", &git_dir),
    ];
    // The fixture writes the listing tests make: init, add, commit.
    let fixture = tmp.path().join("fixture");
    std::fs::create_dir(&fixture).unwrap();
    git_with(&fixture, &["init", "-q"], &leaked);
    put(&fixture, "a.sh", "#!/bin/sh\necho\n");
    git_with(&fixture, &["add", "a.sh"], &leaked);
    git_with(&fixture, &["commit", "-q", "-m", "fixture"], &leaked);
    assert_eq!(
        std::fs::read(&index).unwrap(),
        before,
        "the caller's index changed"
    );
    let listed = git_output(&caller, &["ls-files", "--cached"]).stdout;
    assert_eq!(listed, b"staged.txt\n");
    let listed = git_output(&fixture, &["ls-files", "--cached"]).stdout;
    assert_eq!(listed, b"a.sh\n");
}

/// The fixture repository of the listing tests, and the scripts it holds.
fn fixture_repository(dir: &Path) -> Vec<OsString> {
    git(dir, &["init", "-q"]);
    // Shell scripts, tracked and untracked, inside and outside scripts/,
    // with names that are not UTF-8 or hold a newline.
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
    put(dir, "new\nline.sh", "#!/bin/sh\necho\n");
    put_bytes(dir, b"r\xe9sum\xe9", b"#!/bin/sh\necho\n");
    // Not shell scripts.
    put(dir, "tool.py", "#!/usr/bin/env python3\nprint()\n");
    put(dir, "bashful", "#!/usr/bin/bashful\n");
    put(dir, "notes.txt", "run it with /bin/bash\n");
    put_bytes(dir, b"caf\xe9.txt", b"text\n");
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
            "new\nline.sh",
        ],
    );
    let mut expected = os(&[
        "-helper.sh",
        "bash-eu",
        "deep/er/plain",
        "lib.sh",
        "new\nline.sh",
        "tools/dash-e",
        "tools/env-split",
        "tools/env-split-long",
        "tools/env-split-quoted",
        "untracked-env-sh",
    ]);
    expected.push(OsStr::from_bytes(b"r\xe9sum\xe9").to_owned());
    expected.sort();
    expected
}

#[test]
fn the_listing_finds_scripts_by_name_and_interpreter_and_skips_links_ignored_files_and_embedded_repositories()
 {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("repo");
    std::fs::create_dir(&dir).unwrap();
    let expected = fixture_repository(&dir);
    assert_eq!(linted_shell_scripts(&dir, &dir, &[]), expected);
    // The independent classification of the coverage test agrees.
    assert_eq!(shell_scripts_in_inventory(&dir, &dir, &[]), expected);
}

#[test]
fn a_script_in_merge_conflict_is_listed_once() {
    // git lists a conflicted path once per index stage (three here).
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("repo");
    std::fs::create_dir(&dir).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    put(&dir, "run.sh", "#!/bin/sh\necho base\n");
    git(&dir, &["add", "run.sh"]);
    git(&dir, &["commit", "-q", "-m", "base"]);
    git(&dir, &["checkout", "-q", "-b", "other"]);
    put(&dir, "run.sh", "#!/bin/sh\necho other\n");
    git(&dir, &["commit", "-q", "-am", "other"]);
    git(&dir, &["checkout", "-q", "main"]);
    put(&dir, "run.sh", "#!/bin/sh\necho main\n");
    git(&dir, &["commit", "-q", "-am", "main"]);
    assert!(!git_output(&dir, &["merge", "-q", "other"]).status.success());
    let stages = git_output(&dir, &["ls-files", "--cached"]).stdout;
    assert_eq!(
        String::from_utf8(stages).unwrap(),
        "run.sh\nrun.sh\nrun.sh\n"
    );
    put(&dir, "run.sh", "#!/bin/sh\necho resolved\n");
    let out = check_shell("--list0", &dir, &dir, &[]);
    assert!(out.status.success());
    assert_eq!(out.stdout, b"run.sh\0", "one record, as emitted");
    assert_eq!(shell_scripts_in_inventory(&dir, &dir, &[]), os(&["run.sh"]));
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
    assert_eq!(
        linted_shell_scripts(&dir, &dir, &env),
        os(&["scripts/a.sh"])
    );
    assert_eq!(
        shell_scripts_in_inventory(&dir, &dir, &env),
        os(&["scripts/a.sh"])
    );
    // The human-readable listing names the same scripts, one per line.
    let out = check_shell("--list", &dir, &dir, &env);
    assert!(out.status.success());
    assert_eq!(out.stdout, b"scripts/a.sh\n");
}

#[test]
fn a_listing_that_cannot_be_established_fails() {
    // Not a git work tree: the file list is unknown, never empty.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("plain");
    std::fs::create_dir(&dir).unwrap();
    put(&dir, "x.sh", "#!/bin/sh\necho\n");
    for mode in ["--list", "--list0"] {
        let out = check_shell(mode, &dir, &dir, &[]);
        assert!(!out.status.success(), "{mode} listed {:?}", out.stdout);
        assert!(out.stdout.is_empty());
    }
}

/// The text of `scripts/check-shell.sh`.
fn check_shell_script() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-shell.sh"))
        .unwrap()
}

#[test]
fn the_linter_ignores_caller_configuration() {
    // AGENTS.md: a finding is silenced only by a directive at the command
    // it covers, so no .shellcheckrc (`--norc`) and no SHELLCHECK_OPTS may
    // apply, and a file name is never read as an option (`--`).
    let script = check_shell_script();
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
        assert!(run.starts_with("shellcheck --norc "), "{run}: no --norc");
        assert!(run.contains(" -- \""), "{run}: files not after --");
    }
}

#[test]
fn the_shellcheck_job_lints_every_script_and_cannot_fail_quietly() {
    let text = workflow();
    let block = job(&text, "shellcheck");
    assert!(
        block.contains("scripts/check-shell.sh"),
        "the shellcheck job runs the script the tests above cover"
    );
    assert!(
        block.contains("shellcheck --version"),
        "the job records which shellcheck judged the scripts"
    );
    assert!(
        !block.contains("continue-on-error"),
        "a shellcheck finding must fail the workflow"
    );
    // The cases the lint must fail on cannot be checked in; the self-test
    // builds them and runs them through the same pinned shellcheck.
    let lint = block.find("run: scripts/check-shell.sh").unwrap();
    let selftest = block
        .find("run: scripts/ci/check-shell-selftest.sh")
        .expect("the shellcheck job runs the linter's end-to-end self-test");
    assert!(lint < selftest, "the self-test runs after the lint");
}

/// The shellcheck release `scripts/check-shell.sh` is written against
/// (`SHELLCHECK_VERSION=` in the script).
fn pinned_shellcheck_version() -> String {
    check_shell_script()
        .lines()
        .find_map(|l| l.strip_prefix("SHELLCHECK_VERSION="))
        .expect("check-shell.sh pins SHELLCHECK_VERSION")
        .to_owned()
}

/// The steps of a job, each from its `- ` line to the next one.
fn steps(job: &str) -> Vec<String> {
    let mut steps: Vec<String> = Vec::new();
    for line in job.lines() {
        if line.starts_with("      - ") {
            steps.push(String::new());
        }
        if let Some(step) = steps.last_mut() {
            step.push_str(line);
            step.push('\n');
        }
    }
    steps
}

#[test]
fn ci_installs_the_shellcheck_release_the_script_pins() {
    // Releases differ in what they report (0.11 added SC2329), so CI must
    // not judge with whatever the runner image happens to ship; and the
    // installer that verifies the download is itself pinned to a reviewed
    // commit, with checksum verification stated, not defaulted.
    let version = pinned_shellcheck_version();
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()),
        "SHELLCHECK_VERSION={version} is not an exact release"
    );
    let text = workflow();
    let block = job(&text, "shellcheck");
    let tool = format!("tool: shellcheck@{version}");
    let install: Vec<String> = steps(block)
        .into_iter()
        .filter(|s| s.contains(&tool))
        .collect();
    assert_eq!(install.len(), 1, "one step installs shellcheck {version}");
    let step = &install[0];
    let pinned = step.lines().any(|l| {
        l.trim()
            .strip_prefix("- uses: taiki-e/install-action@")
            .and_then(|rest| rest.split_whitespace().next())
            .is_some_and(|sha| sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
    });
    assert!(
        pinned,
        "the installer is not pinned to a full commit SHA:\n{step}"
    );
    assert!(
        step.lines().any(|l| l.trim() == "checksum: true"),
        "the install step does not state checksum: true:\n{step}"
    );
}
