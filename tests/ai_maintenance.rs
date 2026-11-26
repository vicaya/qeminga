//! The nightly AI maintenance workflow (`.github/workflows/ai-maintenance.yml`,
//! `.github/actions/ai-maintenance/`). Runs the action's offline self-test
//! (key pool, model settings, routing, fallback, the per-attempt sandbox,
//! leak checks, review watch, publishing) and checks the isolation
//! properties of the workflow text: only the agent job sees the key pool,
//! it has no write permission, keeps no credentials and touches no cache,
//! and only the job without keys can write. The privileged test runs
//! attempts in real containers and probes, from inside one, for the other
//! keys and the runner.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn workflow() -> String {
    let path = root().join(".github/workflows/ai-maintenance.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The text of one job: from its key (two-space indent under `jobs:`) to
/// the next key at that indent.
fn job<'a>(text: &'a str, name: &str) -> &'a str {
    let jobs = text.find("\njobs:\n").expect("jobs:");
    let key = format!("\n  {name}:\n");
    let start = jobs
        + text[jobs..]
            .find(&key)
            .unwrap_or_else(|| panic!("no job {name}"))
        + 1;
    let body_start = start + key.len() - 1;
    let end = text[body_start..]
        .lines()
        .scan(0, |offset, line| {
            let at = *offset;
            *offset += line.len() + 1;
            Some((at, line))
        })
        .find(|(_, line)| {
            line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':')
        })
        .map_or(text.len() - body_start, |(at, _)| at);
    &text[start..body_start + end]
}

const JOBS: [&str; 4] = ["watch", "maintain", "publish", "follow-up"];

#[test]
fn the_action_self_test_passes() {
    let script = root().join(".github/actions/ai-maintenance/test/selftest.sh");
    let output = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("{}: {e}", script.display()));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "selftest.sh failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains(" passed, 0 failed"), "{stdout}");
}

#[test]
fn the_workflow_grants_nothing_by_default() {
    let text = workflow();
    assert!(
        text.contains("\npermissions: {}\n"),
        "top-level permissions must be empty"
    );
    for name in JOBS {
        assert!(
            job(&text, name).contains("    permissions:\n"),
            "job {name} must declare its permissions"
        );
    }
}

#[test]
fn the_review_state_travels_as_an_artifact_named_by_its_run() {
    // Dispatch inputs are limited to 65,535 characters in all, and the
    // one-off instructions travel with them: the watch state does not.
    let text = workflow();
    let watch = job(&text, "watch");
    assert!(
        watch.contains("      actions: read\n"),
        "the watch reads the previous run's state artifact"
    );
    assert!(watch.contains("run-id: ${{ inputs.state-run }}"), "{watch}");
    let follow = job(&text, "follow-up");
    assert!(follow.contains("state-run="), "{follow}");
    assert!(
        !text.contains("outputs.until"),
        "the state is not carried as a dispatch input"
    );
}

#[test]
fn only_the_agent_job_sees_the_key_pool_and_it_cannot_write() {
    let text = workflow();
    assert_eq!(
        text.matches("secrets.AI_KEY_POOL").count(),
        1,
        "the pool is passed once"
    );
    let maintain = job(&text, "maintain");
    assert!(maintain.contains("secrets.AI_KEY_POOL"));
    assert!(
        !maintain.contains(": write"),
        "the agent job must not have write permissions"
    );
    assert!(
        !maintain.contains("AI_MAINTENANCE_TOKEN"),
        "the agent job must not get the publishing token"
    );
    // Trusted builds restore caches of the default branch's scope; the
    // agent job neither restores nor saves one.
    for cache in ["rust-cache", "actions/cache", "cache:"] {
        assert!(
            !maintain.contains(cache),
            "the agent job must not use a cache ({cache})"
        );
    }
    // The repository's tools go into the agent's container image.
    assert!(maintain.contains("container-setup: |"));
}

#[test]
fn the_agent_image_has_what_the_repository_checks_run() {
    let text = workflow();
    let maintain = job(&text, "maintain");
    let setup = &maintain[maintain
        .find("container-setup: |")
        .expect("container-setup")..];
    // tests/coverage_gate.rs and scripts/ci/coverage.sh run python3.
    let install = setup
        .lines()
        .find(|l| l.contains("apt-get install"))
        .expect("an apt-get install line");
    assert!(install.contains(" python3"), "{install}");
}

/// Runs `selftest.sh MODE` and expects `PASSED` checks, all passing.
fn selftest_mode(mode: &str, passed: usize) {
    let script = root().join(".github/actions/ai-maintenance/test/selftest.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg(mode)
        .output()
        .unwrap_or_else(|e| panic!("{}: {e}", script.display()));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "selftest.sh {mode} failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(&format!("{passed} passed, 0 failed")),
        "{stdout}"
    );
}

/// Runs attempts in real containers (`selftest.sh --docker`): needs a
/// Docker daemon, which needs root or the docker group, and network access
/// to build the image.
#[test]
#[ignore = "needs a Docker daemon (privileged suite)"]
fn privileged_ai_maintenance_attempts_see_only_their_own_key() {
    selftest_mode("--docker", 5);
}

/// Builds the agent's image with the workflow's repository setup and runs
/// repository checks in an attempt there (`selftest.sh --image`): needs a
/// Docker daemon and network access, and takes several minutes.
#[test]
#[ignore = "needs a Docker daemon (privileged suite)"]
fn privileged_ai_maintenance_image_runs_the_repository_checks() {
    selftest_mode("--image", 3);
}

#[test]
fn the_jobs_that_write_never_see_the_keys_or_run_the_agent() {
    let text = workflow();
    for name in ["publish", "follow-up"] {
        let body = job(&text, name);
        assert!(
            !body.contains("AI_KEY_POOL"),
            "{name} must not see the key pool"
        );
        assert!(
            !body.contains("AI_MAINTENANCE_PROMPT"),
            "{name} must not run the agent"
        );
        assert!(
            !body.contains("uses: ./_ai-maintenance/.github/actions/ai-maintenance\n"),
            "{name} must not run the agent action"
        );
    }
}

#[test]
fn no_checkout_keeps_credentials_and_actions_come_from_the_workflow_commit() {
    let text = workflow();
    for name in JOBS {
        let body = job(&text, name);
        let checkouts = body.matches("uses: actions/checkout@").count();
        assert_eq!(
            body.matches("persist-credentials: false").count(),
            checkouts,
            "every checkout in {name} must use persist-credentials: false"
        );
        // Action code runs from the trusted copy at github.sha, never from
        // the pull request's branch.
        for line in body
            .lines()
            .filter(|l| l.trim_start().starts_with("uses: ./"))
        {
            assert!(line.contains("uses: ./_ai-maintenance/"), "{name}: {line}");
        }
    }
    assert!(text.contains("ACTION_DIR: _ai-maintenance"));
}

#[test]
fn secrets_never_reach_a_shell_script_by_interpolation() {
    let text = workflow();
    // Indent of the `run:` key whose script the current line belongs to.
    let mut run_indent: Option<usize> = None;
    let mut scripts = 0;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if run_indent.is_some_and(|run| !trimmed.is_empty() && indent <= run) {
            run_indent = None;
        }
        if trimmed.starts_with("run:") {
            run_indent = Some(indent);
            scripts += 1;
        }
        if run_indent.is_some() {
            assert!(
                !line.contains("${{"),
                "use env: rather than interpolating into a script: {line}"
            );
        }
    }
    assert!(scripts > 0, "the follow-up job runs a script");
}
