[![Crates.io](https://img.shields.io/crates/v/ese-integrity.svg)](https://crates.io/crates/ese-integrity)
[![Docs.rs](https://img.shields.io/docsrs/ese-integrity?logo=docs.rs)](https://docs.rs/ese-integrity)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://github.com/SecurityRonin/ese-forensic/blob/main/LICENSE)

# ese-integrity

**Structural anomaly detection for ESE / JET Blue databases, built on [`ese-core`](https://crates.io/crates/ese-core).**

Reports raw binary-format facts about an ESE database's health — it never asserts tampering. Detects dirty-shutdown state, page-checksum mismatches, broken B-tree links, data in slack regions, orphaned catalog entries, deleted records, auto-increment gaps, and timestamp skew.

```toml
[dependencies]
ese-integrity = "0.3"
```

```rust
use ese_integrity::EseIntegrity;

let data = std::fs::read("WebCacheV01.dat").unwrap();
for anomaly in EseIntegrity::new(&data).analyse() {
    println!("[{}] {} — {}", anomaly.severity() as u8, anomaly.code(), anomaly);
}
```

Each finding states what was **observed** (the offending bytes, the offset) and a severity; whether that indicates tampering is for the examiner, not this crate. Signatures that expose a value never hide the raw datum.

## Why trust it on hostile input

`#![forbid(unsafe_code)]` (workspace), `unwrap`/`expect` denied outside tests, every offset/length bounds-checked, and a `cargo-fuzz` `fuzz_integrity` must-not-panic target.

Part of [ese-forensic](https://github.com/SecurityRonin/ese-forensic). See also [`ese-core`](https://crates.io/crates/ese-core) (the reader) and [`ese-carver`](https://crates.io/crates/ese-carver) (deleted-record recovery).

---

[Privacy Policy](https://securityronin.github.io/ese-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ese-forensic/terms/) · © 2026 Security Ronin Ltd
