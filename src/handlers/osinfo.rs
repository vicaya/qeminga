//! `guest-get-osinfo` (design §3, §5.5 `uname`; C-5).
//!
//! Returns the kernel release, kernel version and machine architecture
//! from `uname(2)` plus the allowlisted `os-release(5)` fields
//! (`ID`, `NAME`, `PRETTY_NAME`, `VERSION`, `VERSION_ID`, `VARIANT`,
//! `VARIANT_ID`), spelled as in the upstream QAPI `GuestOSInfo` schema.
//! `MACHINE_ID` and every other key are dropped; absent fields are omitted
//! rather than sent as `null`.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use serde_json::{Value, json};

use crate::dispatch::Context;
use crate::handlers::NoArgs;
use crate::proto::{Error, Request, arguments};

/// The three `uname(2)` fields reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uname {
    /// `utsname.release`, e.g. `6.8.0-45-generic`.
    pub release: String,
    /// `utsname.version`, e.g. `#45-Ubuntu SMP ...`.
    pub version: String,
    /// `utsname.machine`, e.g. `x86_64`.
    pub machine: String,
}

/// Where OS information comes from; production reads the kernel and
/// `/etc/os-release`, tests use a fake.
pub trait OsInfoSource: Send + Sync {
    /// Kernel identification.
    fn uname(&self) -> Result<Uname, Error>;
    /// The raw text of `/etc/os-release`, falling back to
    /// `/usr/lib/os-release`; `None` when neither exists.
    fn os_release(&self) -> Option<String>;
}

/// Production source: `nix::sys::utsname::uname` and the two standard
/// `os-release` locations.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemOsInfo;

/// Primary and fallback locations of `os-release(5)`.
pub const OS_RELEASE_PATHS: [&str; 2] = ["/etc/os-release", "/usr/lib/os-release"];

impl OsInfoSource for SystemOsInfo {
    fn uname(&self) -> Result<Uname, Error> {
        let uts = nix::sys::utsname::uname()
            .map_err(|errno| Error::Internal(format!("uname failed: {errno}")))?;
        Ok(Uname {
            release: uts.release().to_string_lossy().into_owned(),
            version: uts.version().to_string_lossy().into_owned(),
            machine: uts.machine().to_string_lossy().into_owned(),
        })
    }

    fn os_release(&self) -> Option<String> {
        os_release_from(&OS_RELEASE_PATHS.map(PathBuf::from))
    }
}

/// Explicit bound on an os-release file (64 KiB): the file is guest-local
/// and normally a few hundred bytes; anything larger is treated as
/// unreadable rather than parsed.
pub const OS_RELEASE_MAX_BYTES: usize = 64 * 1024;

/// Reads one os-release file under [`OS_RELEASE_MAX_BYTES`]. A file over
/// the bound or not valid UTF-8 is an `InvalidData` error; a missing one
/// is `NotFound`.
fn read_os_release(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(OS_RELEASE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > OS_RELEASE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "os-release file larger than the bound",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "os-release is not UTF-8"))
}

/// The first readable file of `paths`, per os-release(5): a later path is
/// tried only when the earlier one is **missing**. Any other failure
/// (permissions, size, encoding) is reported and yields `None`, so the
/// reply carries the kernel fields only rather than a stale vendor file.
fn os_release_from(paths: &[PathBuf]) -> Option<String> {
    for path in paths {
        match read_os_release(path) {
            Ok(text) => return Some(text),
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                tracing::warn!(
                    event = "os_release_unreadable",
                    path = %path.display(),
                    error = %err,
                    "os-release file unreadable; reporting kernel fields only"
                );
                return None;
            }
        }
    }
    None
}

/// Parses `os-release(5)` text into `KEY → value`.
///
/// Comment and blank lines are skipped; keys are `[A-Za-z0-9_]+`; values
/// may be unquoted, single-quoted (literal) or double-quoted (backslash
/// escapes exactly `\"`, `\\`, `\$`, `` \` ``; before any other character
/// the backslash is literal, as in the shell); anything after a closing
/// quote is ignored; a later assignment overrides an earlier one. Never
/// panics.
pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        map.insert(key.to_owned(), unquote(raw.trim()));
    }
    map
}

/// Decodes one value per the quoting rules above.
fn unquote(raw: &str) -> String {
    let mut chars = raw.chars();
    match chars.next() {
        Some('\'') => chars.take_while(|&c| c != '\'').collect(),
        Some('"') => {
            let mut out = String::new();
            let mut escaped = false;
            for c in chars {
                if escaped {
                    if !matches!(c, '$' | '`' | '"' | '\\') {
                        out.push('\\');
                    }
                    out.push(c);
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    break;
                } else {
                    out.push(c);
                }
            }
            if escaped {
                out.push('\\');
            }
            out
        }
        _ => {
            let mut out = String::new();
            let mut escaped = false;
            for c in raw.chars() {
                if escaped {
                    out.push(c);
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else {
                    out.push(c);
                }
            }
            out
        }
    }
}

/// The QAPI `GuestOSInfo` reply (C-5). Absent fields are omitted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OsInfo {
    /// `uname` release.
    #[serde(rename = "kernel-release", skip_serializing_if = "Option::is_none")]
    pub kernel_release: Option<String>,
    /// `uname` version.
    #[serde(rename = "kernel-version", skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    /// `uname` machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// `ID`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `NAME`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `PRETTY_NAME`.
    #[serde(rename = "pretty-name", skip_serializing_if = "Option::is_none")]
    pub pretty_name: Option<String>,
    /// `VERSION`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `VERSION_ID`.
    #[serde(rename = "version-id", skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// `VARIANT`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// `VARIANT_ID`.
    #[serde(rename = "variant-id", skip_serializing_if = "Option::is_none")]
    pub variant_id: Option<String>,
}

/// Assembles the reply from a source; only the allowlisted keys are copied.
pub fn os_info(source: &dyn OsInfoSource) -> Result<OsInfo, Error> {
    let uname = source.uname()?;
    let mut fields = source
        .os_release()
        .map(|text| parse_os_release(&text))
        .unwrap_or_default();
    Ok(OsInfo {
        kernel_release: Some(uname.release),
        kernel_version: Some(uname.version),
        machine: Some(uname.machine),
        id: fields.remove("ID"),
        name: fields.remove("NAME"),
        pretty_name: fields.remove("PRETTY_NAME"),
        version: fields.remove("VERSION"),
        version_id: fields.remove("VERSION_ID"),
        variant: fields.remove("VARIANT"),
        variant_id: fields.remove("VARIANT_ID"),
    })
}

/// `guest-get-osinfo` handler.
pub async fn handle(ctx: &Context, req: &Request) -> Result<Value, Error> {
    let NoArgs {} = arguments(req)?;
    let source: Arc<dyn OsInfoSource> = Arc::clone(&ctx.osinfo);
    Ok(json!(os_info(source.as_ref())?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/os-release")
                .join(name),
        )
        .unwrap()
    }

    struct Fake {
        uname: Uname,
        etc: Option<String>,
        usr_lib: Option<String>,
    }

    impl Fake {
        fn new(etc: Option<&str>, usr_lib: Option<&str>) -> Self {
            Fake {
                uname: Uname {
                    release: "6.8.0-test".into(),
                    version: "#1 SMP PREEMPT_DYNAMIC".into(),
                    machine: "x86_64".into(),
                },
                etc: etc.map(str::to_owned),
                usr_lib: usr_lib.map(str::to_owned),
            }
        }
    }

    impl OsInfoSource for Fake {
        fn uname(&self) -> Result<Uname, Error> {
            Ok(self.uname.clone())
        }
        fn os_release(&self) -> Option<String> {
            self.etc.clone().or_else(|| self.usr_lib.clone())
        }
    }

    #[test]
    fn os_release_file_reads_are_bounded_and_only_absence_falls_through() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert_eq!(
            read_os_release(&missing).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let ok = dir.path().join("ok");
        std::fs::write(&ok, "ID=x\n").unwrap();
        assert_eq!(read_os_release(&ok).unwrap(), "ID=x\n");
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'#'; OS_RELEASE_MAX_BYTES + 1]).unwrap();
        assert_eq!(
            read_os_release(&big).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        let binary = dir.path().join("binary");
        std::fs::write(&binary, b"ID=\xff\n").unwrap();
        assert_eq!(
            read_os_release(&binary).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        // The production source falls through to the next path only when
        // the first is missing; any other failure yields no text at all.
        assert_eq!(
            os_release_from(&[missing.clone(), ok.clone()]).as_deref(),
            Some("ID=x\n")
        );
        assert_eq!(os_release_from(&[big, ok.clone()]), None);
        assert_eq!(os_release_from(&[missing.clone(), missing]), None);
    }

    #[test]
    fn parse_os_release_handles_quotes_and_escapes() {
        let map = parse_os_release(&fixture("quoted.txt"));
        assert_eq!(map["NAME"], "Single Quoted \"Name\"");
        assert_eq!(map["ID"], "spaced");
        assert_eq!(map["PRETTY_NAME"], "Double Quoted 'Name' # not a comment");
        assert_eq!(map["VERSION"], "12 (bookworm)");
        assert_eq!(map["VERSION_ID"], "12");
        assert_eq!(map["VARIANT"], "unquoted value with spaces");
        assert_eq!(map["VARIANT_ID"], "server");
        assert_eq!(map["MACHINE_ID"], "must-never-be-emitted");

        let map = parse_os_release(&fixture("escaped.txt"));
        assert_eq!(map["NAME"], "Foo \"Bar\"");
        assert_eq!(
            map["PRETTY_NAME"],
            "Cost: $5 and a \\ backslash and a ` backtick"
        );
        assert_eq!(map["ID"], "escaped$id");
        assert_eq!(map["VERSION"], "lit\\eral", "single quotes are literal");
        assert_eq!(map["VERSION_ID"], "unterminated");
        // Inside double quotes a backslash is literal unless it precedes
        // one of `$`, `` ` ``, `"`, `\` (shell rules, as os-release(5) says).
        assert_eq!(map["VARIANT"], "Foo\\Bar 1.0 with \\n kept");

        // Real-world files.
        let debian = parse_os_release(&fixture("debian.txt"));
        assert_eq!(debian["PRETTY_NAME"], "Debian GNU/Linux 12 (bookworm)");
        assert_eq!(debian["ID"], "debian");
        let fedora = parse_os_release(&fixture("fedora.txt"));
        assert_eq!(fedora["VARIANT_ID"], "server");
        assert_eq!(fedora["VERSION_CODENAME"], "");

        // Malformed lines are skipped, later keys win.
        let map = parse_os_release("NOEQUALS\n=novalue\nBAD KEY=1\nID=a\nID=b\n#ID=c\n");
        assert_eq!(map.len(), 1);
        assert_eq!(map["ID"], "b");
    }

    #[test]
    fn only_whitelisted_keys_are_emitted() {
        let info = os_info(&Fake::new(Some(&fixture("quoted.txt")), None)).unwrap();
        let value = json!(info);
        let obj = value.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "id",
                "kernel-release",
                "kernel-version",
                "machine",
                "name",
                "pretty-name",
                "variant",
                "variant-id",
                "version",
                "version-id",
            ]
        );
        assert!(!value.to_string().contains("must-never-be-emitted"));
        let fedora = json!(os_info(&Fake::new(Some(&fixture("fedora.txt")), None)).unwrap());
        assert!(fedora.get("machine-id").is_none());
        assert!(fedora.get("home-url").is_none());
        assert!(fedora.get("HOME_URL").is_none());
        assert_eq!(fedora["variant"], "Server Edition");
    }

    #[test]
    fn missing_file_falls_back_to_usr_lib() {
        let info = os_info(&Fake::new(None, Some(&fixture("debian.txt")))).unwrap();
        assert_eq!(info.id.as_deref(), Some("debian"));
        // /etc wins when both exist.
        let info = os_info(&Fake::new(
            Some(&fixture("fedora.txt")),
            Some(&fixture("debian.txt")),
        ))
        .unwrap();
        assert_eq!(info.id.as_deref(), Some("fedora"));
    }

    #[test]
    fn missing_both_yields_kernel_fields_only() {
        let info = os_info(&Fake::new(None, None)).unwrap();
        let value = json!(info);
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["kernel-release", "kernel-version", "machine"]);
        // An empty file behaves the same.
        let info = os_info(&Fake::new(Some(&fixture("empty.txt")), None)).unwrap();
        assert_eq!(json!(info), value);
    }

    #[test]
    fn output_uses_qapi_field_names_and_omits_absent_fields() {
        let info = os_info(&Fake::new(Some("ID=x\nVERSION_ID=1\n"), None)).unwrap();
        let value = json!(info);
        assert_eq!(value["id"], "x");
        assert_eq!(value["version-id"], "1");
        assert!(value.get("name").is_none());
        assert!(value.get("pretty-name").is_none());
        assert!(!value.to_string().contains("null"));
        assert!(!value.to_string().contains("version_id"));
    }

    #[test]
    fn uname_fields_are_mapped() {
        let info = os_info(&Fake::new(None, None)).unwrap();
        let value = json!(info);
        assert_eq!(value["kernel-release"], "6.8.0-test");
        assert_eq!(value["kernel-version"], "#1 SMP PREEMPT_DYNAMIC");
        assert_eq!(value["machine"], "x86_64");
    }

    #[test]
    fn system_source_reads_the_running_kernel() {
        let uname = SystemOsInfo.uname().unwrap();
        assert!(!uname.release.is_empty());
        assert!(!uname.machine.is_empty());
        // The source never fails on a missing os-release; it just yields None.
        let _ = SystemOsInfo.os_release();
    }

    #[tokio::test]
    async fn handler_uses_context_source_and_rejects_arguments() {
        let ctx = Context::for_tests()
            .with_osinfo(Arc::new(Fake::new(Some(&fixture("debian.txt")), None)));
        let req = crate::proto::parse_request(br#"{"execute":"guest-get-osinfo"}"#).unwrap();
        let value = handle(&ctx, &req).await.unwrap();
        assert_eq!(value["id"], "debian");
        assert_eq!(value["machine"], "x86_64");
        let req =
            crate::proto::parse_request(br#"{"execute":"guest-get-osinfo","arguments":{"a":1}}"#)
                .unwrap();
        assert!(matches!(
            handle(&ctx, &req).await,
            Err(Error::InvalidArguments(_))
        ));
    }

    proptest! {
        #[test]
        fn parser_never_panics(text in "\\PC*") {
            let map = parse_os_release(&text);
            for (key, _) in map {
                prop_assert!(key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
            }
        }

        #[test]
        fn parser_never_panics_on_structured_input(
            lines in prop::collection::vec("[A-Z_]{0,8}=[\"']?[^\\n]{0,40}[\"']?", 0..20)
        ) {
            let text = lines.join("\n");
            let _ = parse_os_release(&text);
            let _ = os_info(&Fake::new(Some(&text), None)).unwrap();
        }
    }
}
