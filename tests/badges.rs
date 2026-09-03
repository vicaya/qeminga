//! `scripts/ci/badge.sh` renders the README badges (T5.7); it must produce
//! well-formed SVG without a network or an external service.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

fn badge(args: &[&str]) -> String {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci/badge.sh");
    let output = Command::new("sh").arg(script).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "badge.sh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn badge_renders_label_value_and_colour() {
    let svg = badge(&["coverage", "93.4%", "brightgreen"]);
    assert!(
        svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""),
        "{svg}"
    );
    assert!(svg.trim_end().ends_with("</svg>"), "{svg}");
    assert!(svg.contains("aria-label=\"coverage: 93.4%\""), "{svg}");
    assert!(
        svg.contains("fill=\"#4c1\""),
        "named colour is mapped: {svg}"
    );
    // Both texts are drawn twice (shadow and face).
    assert_eq!(svg.matches(">coverage</text>").count(), 2, "{svg}");
    assert_eq!(svg.matches(">93.4%</text>").count(), 2, "{svg}");
    // The overall width is the sum of the two panels.
    let width = |attr: &str| -> u32 {
        let start = svg.find(attr).unwrap() + attr.len();
        svg[start..].split('"').next().unwrap().parse().unwrap()
    };
    let total = width("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"");
    let label = width("<rect x=\"");
    let value = width(&format!("<rect x=\"{label}\" width=\""));
    assert_eq!(total, label + value);
    assert_eq!(label, "coverage".len() as u32 * 7 + 10);
    assert_eq!(value, "93.4%".len() as u32 * 7 + 10);
    // A raw CSS colour passes through unchanged.
    let svg = badge(&["tests", "275 passed", "#123456"]);
    assert!(svg.contains("fill=\"#123456\""), "{svg}");
}

#[test]
fn badge_escapes_markup_in_text() {
    let svg = badge(&["a<b", "c&d>e", "red"]);
    assert!(svg.contains(">a&lt;b</text>"), "{svg}");
    assert!(svg.contains(">c&amp;d&gt;e</text>"), "{svg}");
    assert!(
        !svg.contains("<b"),
        "unescaped '<' would break the SVG: {svg}"
    );
    assert!(svg.contains("fill=\"#e05d44\""), "{svg}");
}
