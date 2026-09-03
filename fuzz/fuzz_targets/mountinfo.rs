//! Fuzz target: the `/proc/self/mountinfo` parser and the freeze plan
//! built from it (design §4.2, AC14). Never panics; the plan only ever
//! contains eligible entries and stays deduplicated by device.
#![forbid(unsafe_code)]
#![no_main]

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use qeminga::freeze_plan::{FREEZABLE_FS_TYPES, FreezePlan};
use qeminga::mountinfo::{parse_mountinfo, unescape};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        let _ = unescape(&String::from_utf8_lossy(data));
        return;
    };
    let entries = parse_mountinfo(text);
    assert!(entries.len() <= text.lines().count());
    let plan = FreezePlan::build(&entries);
    let mut devs = HashSet::new();
    for target in plan.targets() {
        assert!(FREEZABLE_FS_TYPES.contains(&target.fs_type.as_str()));
        assert!(devs.insert(target.dev), "duplicate device in plan");
    }
    assert_eq!(plan.freeze_order().count(), plan.thaw_order().count());
    let _ = plan.covers(std::path::Path::new("/run/qeminga/frozen"));
    let _ = unescape(text);
});
