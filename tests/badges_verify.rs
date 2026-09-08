//! `scripts/ci/verify-badges-render.sh` (T5.7) against a scripted `curl`:
//! the rendered README must carry exactly the two published badges, each
//! once, as same-repository raw URLs that GitHub serves as SVG.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const REPO: &str = "vicaya/qeminga";

fn img(file: &str) -> String {
    format!("<img src=\"https://github.com/{REPO}/raw/badges/main/{file}\" alt=\"x\">")
}

/// Runs the verifier with a `curl` that answers the README request with
/// `readme_html` and every raw request with the given status and type.
fn verify(readme_html: &str, raw_status: &str, raw_type: &str) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("readme.html"), readme_html).unwrap();
    let curl = dir.path().join("curl");
    std::fs::write(
        &curl,
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do url=$a; done\ncase \"$url\" in\n  https://api.github.com/*) cat '{readme}' ;;\n  https://raw.githubusercontent.com/*) printf 'HTTP/2 {status}\\r\\ncontent-type: {ctype}\\r\\n\\r\\n' ;;\n  *) echo \"unexpected url $url\" >&2; exit 22 ;;\nesac\n",
            readme = dir.path().join("readme.html").display(),
            status = raw_status,
            ctype = raw_type,
        ),
    )
    .unwrap();
    let mut perm = std::fs::metadata(&curl).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&curl, perm).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci/verify-badges-render.sh");
    let out = Command::new("sh")
        .arg(script)
        .args([REPO, "main"])
        .env(
            "PATH",
            format!(
                "{}:{}",
                dir.path().display(),
                std::env::var("PATH").unwrap()
            ),
        )
        .env("GH_TOKEN", "t")
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn both_badges_served_as_svg_pass() {
    let html = format!("<p>{}{}</p>", img("tests.svg"), img("coverage.svg"));
    let (ok, text) = verify(&html, "200", "image/svg+xml");
    assert!(ok, "{text}");
    assert!(text.contains("badges/main/tests.svg"), "{text}");
    assert!(text.contains("badges/main/coverage.svg"), "{text}");
}

#[test]
fn a_missing_badge_fails() {
    let html = format!("<p>{}</p>", img("coverage.svg"));
    let (ok, text) = verify(&html, "200", "image/svg+xml");
    assert!(!ok, "{text}");
    assert!(
        text.contains("tests.svg"),
        "names the missing badge: {text}"
    );
}

#[test]
fn a_duplicated_badge_fails() {
    let html = format!(
        "<p>{}{}{}</p>",
        img("tests.svg"),
        img("coverage.svg"),
        img("coverage.svg")
    );
    let (ok, text) = verify(&html, "200", "image/svg+xml");
    assert!(!ok, "{text}");
    assert!(text.contains("more than once"), "{text}");
}

#[test]
fn a_rewritten_or_foreign_badge_url_fails() {
    let html = format!(
        "<p>{}<img src=\"https://camo.githubusercontent.com/abc/coverage.svg\"></p>",
        img("tests.svg")
    );
    let (ok, text) = verify(&html, "200", "image/svg+xml");
    assert!(!ok, "{text}");
    assert!(text.contains("unexpected badge URL"), "{text}");
}

#[test]
fn a_badge_not_served_as_svg_fails() {
    let html = format!("<p>{}{}</p>", img("tests.svg"), img("coverage.svg"));
    let (ok, text) = verify(&html, "404", "text/plain");
    assert!(!ok, "{text}");
    assert!(text.contains("not served as SVG"), "{text}");
}
