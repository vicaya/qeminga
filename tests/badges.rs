//! `scripts/ci/badge.sh` renders the README badges (T5.7); it must produce
//! well-formed SVG without a network or an external service.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Stdio};

fn badge_output(args: &[&str]) -> std::process::Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci/badge.sh");
    Command::new("sh").arg(script).args(args).output().unwrap()
}

fn badge(args: &[&str]) -> String {
    let output = badge_output(args);
    assert!(
        output.status.success(),
        "badge.sh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Parses `svg` with a real XML parser (xmllint, else python's
/// xml.etree); a malformed document fails the test.
fn assert_well_formed_xml(svg: &str) {
    use std::io::Write;
    let mut child = match Command::new("xmllint")
        .args(["--noout", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => Command::new("python3")
            .args([
                "-c",
                "import sys, xml.etree.ElementTree as E; E.fromstring(sys.stdin.read())",
            ])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("xmllint or python3"),
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(svg.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "not well-formed XML: {}\n{svg}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn badge_renders_label_value_and_colour() {
    let svg = badge(&["coverage", "93.4%", "brightgreen"]);
    assert_well_formed_xml(&svg);
    assert!(
        svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""),
        "{svg}"
    );
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
    // A hexadecimal colour passes through unchanged.
    let svg = badge(&["tests", "275 passed", "#123456"]);
    assert_well_formed_xml(&svg);
    assert!(svg.contains("fill=\"#123456\""), "{svg}");
}

#[test]
fn badge_escapes_markup_and_quotes_in_text() {
    let svg = badge(&["a<b", "c&d>e", "red"]);
    assert_well_formed_xml(&svg);
    assert!(svg.contains(">a&lt;b</text>"), "{svg}");
    assert!(svg.contains(">c&amp;d&gt;e</text>"), "{svg}");
    assert!(svg.contains("fill=\"#e05d44\""), "{svg}");
    // Quotes land inside attribute values (aria-label) as well as content.
    let svg = badge(&["say \"hi\"", "it's", "grey"]);
    assert_well_formed_xml(&svg);
    assert!(
        svg.contains("aria-label=\"say &quot;hi&quot;: it&apos;s\""),
        "{svg}"
    );
    assert!(svg.contains(">say &quot;hi&quot;</text>"), "{svg}");
}

#[test]
fn badge_rejects_colours_outside_the_palette_or_hex_form() {
    for bad in ["purple", "#12345g", "#12", "red; onload=x", "url(#s)"] {
        let out = badge_output(&["x", "y", bad]);
        assert_eq!(out.status.code(), Some(2), "{bad}");
        assert!(out.stdout.is_empty(), "{bad}: nothing rendered");
    }
    for good in ["#abc", "#AbCdEf", "yellowgreen", "orange"] {
        assert_well_formed_xml(&badge(&["x", "y", good]));
    }
}
