//! `scripts/ci/publish-badges.sh` (T5.7) against temporary bare
//! repositories: first publication creates the orphan branch, unchanged
//! output publishes nothing, an existing branch directory is updated,
//! branches get separate directories, and a publication that lands while
//! another is in flight is retried on the new tip instead of failing.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

struct Rig {
    _dir: tempfile::TempDir,
    remote: PathBuf,
    clone: PathBuf,
    inputs: PathBuf,
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@x")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@x")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

impl Rig {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("remote.git");
        git(
            dir.path(),
            &["init", "-q", "--bare", remote.to_str().unwrap()],
        );
        // A working clone with one commit, as the CI checkout would be.
        let clone = dir.path().join("clone");
        git(
            dir.path(),
            &["init", "-q", "-b", "main", clone.to_str().unwrap()],
        );
        std::fs::write(clone.join("README"), "x").unwrap();
        git(&clone, &["add", "README"]);
        git(&clone, &["commit", "-q", "-m", "init"]);
        git(
            &clone,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        let inputs = dir.path().join("inputs");
        std::fs::create_dir(&inputs).unwrap();
        Rig {
            _dir: dir,
            remote,
            clone,
            inputs,
        }
    }

    fn inputs(&self, percent: f64, passed: u32) -> (PathBuf, PathBuf) {
        let json = self.inputs.join("coverage-summary.json");
        std::fs::write(
            &json,
            format!(r#"{{"production_lines":{{"percent":{percent}}},"all_lines":{{}}}}"#),
        )
        .unwrap();
        let log = self.inputs.join("coverage.log");
        std::fs::write(
            &log,
            format!("test result: ok. {passed} passed; 0 failed\ntest result: ok. 0 passed\n"),
        )
        .unwrap();
        (json, log)
    }

    fn head(&self) -> String {
        git(&self.clone, &["rev-parse", "HEAD"]).trim().to_owned()
    }

    /// Makes the clone's HEAD the tip of `branch` on the remote, as the
    /// pushed commit of a CI run is.
    fn push_source(&self, branch: &str) {
        git(
            &self.clone,
            &["push", "-q", "origin", &format!("HEAD:refs/heads/{branch}")],
        );
    }

    fn publish(
        &self,
        branch: &str,
        percent: f64,
        passed: u32,
        hook: Option<&str>,
    ) -> (bool, String) {
        self.push_source(branch);
        let sha = self.head();
        self.publish_sha(branch, &sha, percent, passed, hook)
    }

    fn publish_sha(
        &self,
        branch: &str,
        sha: &str,
        percent: f64,
        passed: u32,
        hook: Option<&str>,
    ) -> (bool, String) {
        let (json, log) = self.inputs(percent, passed);
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci/publish-badges.sh");
        let mut cmd = Command::new("sh");
        cmd.arg(script)
            .arg(branch)
            .arg(sha)
            .arg(&json)
            .arg(&log)
            .current_dir(&self.clone)
            .env("GIT_AUTHOR_NAME", "bot")
            .env("GIT_AUTHOR_EMAIL", "bot@x")
            .env("GIT_COMMITTER_NAME", "bot")
            .env("GIT_COMMITTER_EMAIL", "bot@x")
            .env("BADGES_ATTEMPTS", "3");
        if let Some(hook) = hook {
            cmd.env("BADGES_BEFORE_PUSH", hook);
        }
        let out = cmd.output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    fn files(&self) -> Vec<String> {
        git(
            &self.clone,
            &[
                "--git-dir",
                self.remote.to_str().unwrap(),
                "ls-tree",
                "-r",
                "--name-only",
                "badges",
            ],
        )
        .lines()
        .map(str::to_owned)
        .collect()
    }

    fn show(&self, path: &str) -> String {
        git(
            &self.clone,
            &[
                "--git-dir",
                self.remote.to_str().unwrap(),
                "show",
                &format!("badges:{path}"),
            ],
        )
    }

    fn commits(&self) -> usize {
        git(
            &self.clone,
            &[
                "--git-dir",
                self.remote.to_str().unwrap(),
                "rev-list",
                "--count",
                "badges",
            ],
        )
        .trim()
        .parse()
        .unwrap()
    }
}

#[test]
fn first_publication_creates_the_orphan_branch() {
    let rig = Rig::new();
    let (ok, text) = rig.publish("main", 90.53, 300, None);
    assert!(ok, "{text}");
    assert!(text.contains("published main"), "{text}");
    assert_eq!(
        rig.files(),
        ["main/coverage.svg", "main/summary.json", "main/tests.svg"]
    );
    assert_eq!(rig.commits(), 1, "an orphan branch with one commit");
    assert!(
        rig.show("main/summary.json")
            .contains("\"production_lines_percent\":90.5")
    );
    assert!(rig.show("main/coverage.svg").contains(">90.5%</text>"));
    assert!(rig.show("main/tests.svg").contains(">300 passed</text>"));
}

#[test]
fn unchanged_output_publishes_nothing() {
    let rig = Rig::new();
    assert!(rig.publish("main", 90.5, 300, None).0);
    let (ok, text) = rig.publish("main", 90.5, 300, None);
    assert!(ok, "{text}");
    assert!(text.contains("badges unchanged"), "{text}");
    assert_eq!(rig.commits(), 1);
}

#[test]
fn existing_branch_directory_is_updated_and_branches_are_separate() {
    let rig = Rig::new();
    assert!(rig.publish("main", 90.5, 300, None).0);
    assert!(rig.publish("task/t9.9-x", 70.2, 12, None).0);
    let (ok, text) = rig.publish("main", 91.0, 301, None);
    assert!(ok, "{text}");
    assert_eq!(rig.commits(), 3);
    let files = rig.files();
    assert!(
        files.contains(&"task/t9.9-x/coverage.svg".to_owned()),
        "{files:?}"
    );
    assert!(rig.show("main/coverage.svg").contains(">91.0%</text>"));
    assert!(rig.show("main/tests.svg").contains(">301 passed</text>"));
    assert!(
        rig.show("task/t9.9-x/coverage.svg")
            .contains(">70.2%</text>")
    );
    assert!(
        rig.show("task/t9.9-x/coverage.svg").contains("#a4a61d"),
        "yellowgreen"
    );
}

#[test]
fn a_concurrent_publication_is_retried_on_the_new_tip() {
    // The hook runs before each push attempt and, once, publishes a
    // different value for the same branch from a second clone, so the
    // first push is rejected; the script must regenerate on the new tip.
    let rig = Rig::new();
    assert!(rig.publish("main", 80.0, 100, None).0);
    // A second CI checkout of the same repository.
    let other = rig._dir.path().join("other");
    git(
        rig._dir.path(),
        &[
            "clone",
            "-q",
            rig.clone.to_str().unwrap(),
            other.to_str().unwrap(),
        ],
    );
    git(
        &other,
        &["remote", "set-url", "origin", rig.remote.to_str().unwrap()],
    );
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci/publish-badges.sh");
    let (json2, log2) = {
        let dir = rig._dir.path().join("inputs2");
        std::fs::create_dir(&dir).unwrap();
        let j = dir.join("s.json");
        std::fs::write(&j, r#"{"production_lines":{"percent":85.0}}"#).unwrap();
        let l = dir.join("c.log");
        std::fs::write(&l, "test result: ok. 200 passed\n").unwrap();
        (j, l)
    };
    let once = rig._dir.path().join("hook-ran");
    let hook = format!(
        "[ -e '{once}' ] || {{ touch '{once}'; cd '{other}' && GIT_AUTHOR_NAME=o GIT_AUTHOR_EMAIL=o@x GIT_COMMITTER_NAME=o GIT_COMMITTER_EMAIL=o@x sh '{script}' main {sha} '{json}' '{log}' >/dev/null; }}",
        once = once.display(),
        sha = rig.head(),
        other = other.display(),
        script = script.display(),
        json = json2.display(),
        log = log2.display()
    );
    let (ok, text) = rig.publish("main", 90.0, 300, Some(&hook));
    assert!(ok, "{text}");
    assert!(
        text.contains("push rejected"),
        "first push must have been rejected: {text}"
    );
    assert!(text.contains("attempt 2"), "{text}");
    // Three publications in order, the last one wins, nothing was lost.
    assert_eq!(rig.commits(), 3);
    assert!(rig.show("main/coverage.svg").contains(">90.0%</text>"));
    let log = git(
        &rig.clone,
        &[
            "--git-dir",
            rig.remote.to_str().unwrap(),
            "log",
            "--format=%s",
            "badges",
        ],
    );
    assert!(log.contains("85.0% production lines"), "{log}");
}

#[test]
fn gives_up_after_the_attempt_budget() {
    let rig = Rig::new();
    assert!(rig.publish("main", 80.0, 100, None).0);
    // A hook that always lands a fresh commit on the badges branch.
    let hook = format!(
        "d=$(mktemp -d) && git -C $d init -q && git -C $d fetch -q '{remote}' badges && git -C $d checkout -q FETCH_HEAD && date +%s%N > $d/bump && git -C $d add bump && GIT_AUTHOR_NAME=o GIT_AUTHOR_EMAIL=o@x GIT_COMMITTER_NAME=o GIT_COMMITTER_EMAIL=o@x git -C $d commit -q -m bump && git -C $d push -q '{remote}' HEAD:refs/heads/badges",
        remote = rig.remote.display()
    );
    let (ok, text) = rig.publish("main", 90.0, 300, Some(&hook));
    assert!(!ok, "{text}");
    assert!(text.contains("giving up"), "{text}");
}

#[test]
fn a_failed_git_add_is_an_error_not_unchanged_badges() {
    // A `git` on PATH that fails `add` and forwards everything else: the
    // publisher must fail loudly rather than report the badges unchanged.
    let rig = Rig::new();
    assert!(rig.publish("main", 80.0, 100, None).0);
    let bin = rig._dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let real = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v git"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let shim = bin.join("git");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = -C ] && [ \"${{3:-}}\" = add ]; then echo 'git add: simulated I/O error' >&2; exit 128; fi\nexec {} \"$@\"\n",
            real.trim()
        ),
    )
    .unwrap();
    let mut perm = std::fs::metadata(&shim).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perm.set_mode(0o755);
    std::fs::set_permissions(&shim, perm).unwrap();
    let (json, log) = rig.inputs(90.0, 300);
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci/publish-badges.sh");
    let out = Command::new("sh")
        .arg(script)
        .args([
            "main",
            &rig.head(),
            json.to_str().unwrap(),
            log.to_str().unwrap(),
        ])
        .current_dir(&rig.clone)
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("GIT_AUTHOR_NAME", "bot")
        .env("GIT_AUTHOR_EMAIL", "bot@x")
        .env("GIT_COMMITTER_NAME", "bot")
        .env("GIT_COMMITTER_EMAIL", "bot@x")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{text}");
    assert!(!text.contains("badges unchanged"), "{text}");
    assert!(text.contains("simulated I/O error"), "{text}");
    assert_eq!(rig.commits(), 1, "nothing was published");
}

#[test]
fn a_publication_for_a_superseded_source_commit_is_skipped() {
    // Coverage for commit A was still running when B was pushed and
    // published; A's publisher must notice that the source branch moved
    // on and leave B's badges alone.
    let rig = Rig::new();
    let sha_a = rig.head();
    rig.push_source("main");
    std::fs::write(rig.clone.join("b"), "b").unwrap();
    git(&rig.clone, &["add", "b"]);
    git(&rig.clone, &["commit", "-q", "-m", "B"]);
    let (ok, text) = rig.publish("main", 91.0, 301, None);
    assert!(ok, "{text}");
    assert_eq!(rig.commits(), 1);
    let (ok, text) = rig.publish_sha("main", &sha_a, 80.0, 100, None);
    assert!(ok, "a superseded publication is not a failure: {text}");
    assert!(text.contains("superseded"), "{text}");
    assert!(!text.contains("published main"), "{text}");
    assert_eq!(rig.commits(), 1, "B's badges were not overwritten");
    assert!(rig.show("main/coverage.svg").contains(">91.0%</text>"));
}

#[test]
fn the_source_branch_advancing_during_a_retry_skips_the_publication() {
    // The first push is rejected by a concurrent badges publication; by
    // the time the publisher retries, the source branch has moved on.
    let rig = Rig::new();
    assert!(rig.publish("main", 80.0, 100, None).0);
    let sha_a = rig.head();
    let bump = format!(
        "d=$(mktemp -d) && git -C $d init -q && git -C $d fetch -q '{remote}' badges && git -C $d checkout -q FETCH_HEAD && date +%s%N > $d/bump && git -C $d add bump && GIT_AUTHOR_NAME=o GIT_AUTHOR_EMAIL=o@x GIT_COMMITTER_NAME=o GIT_COMMITTER_EMAIL=o@x git -C $d commit -q -m bump && git -C $d push -q '{remote}' HEAD:refs/heads/badges",
        remote = rig.remote.display()
    );
    // The hook runs before each push attempt: the first call lands a
    // competing badges commit (so the first push is rejected), the second
    // call, during the retry, advances the source branch.
    let calls = rig._dir.path().join("hook-calls");
    let hook = format!(
        "if [ ! -e '{calls}' ]; then touch '{calls}'; {bump}; else cd '{clone}' && git commit -q --allow-empty -m B && git push -q origin HEAD:refs/heads/main; fi",
        calls = calls.display(),
        clone = rig.clone.display(),
    );
    let (ok, text) = rig.publish_sha("main", &sha_a, 90.0, 300, Some(&hook));
    assert!(ok, "{text}");
    assert!(text.contains("push rejected"), "{text}");
    assert!(text.contains("superseded"), "{text}");
    assert!(!text.contains("published main"), "{text}");
    assert!(rig.show("main/coverage.svg").contains(">80.0%</text>"));
}

#[test]
fn a_source_branch_missing_from_the_remote_is_not_published() {
    let rig = Rig::new();
    let (ok, text) = rig.publish_sha("gone", &rig.head(), 90.0, 300, None);
    assert!(ok, "{text}");
    assert!(text.contains("superseded"), "{text}");
    let out = Command::new("git")
        .args([
            "--git-dir",
            rig.remote.to_str().unwrap(),
            "rev-parse",
            "--verify",
            "badges",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "no badges branch was created");
}
