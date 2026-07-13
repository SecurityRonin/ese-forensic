[![Crates.io](https://img.shields.io/crates/v/ese-carver.svg)](https://crates.io/crates/ese-carver)
[![Docs.rs](https://img.shields.io/docsrs/ese-carver?logo=docs.rs)](https://docs.rs/ese-carver)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://github.com/SecurityRonin/ese-forensic/blob/main/LICENSE)

# ese-carver

**Recover ESE records fragmented across page boundaries, built on [`ese-core`](https://crates.io/crates/ese-core).**

When an ESE record spans pages, or a page is partially overwritten, the fragments survive on disk as prefix/suffix tag pairs. `ese-carver` detects those pairs and reconstructs the original record — recovering data the normal B-tree walk no longer reaches.

```toml
[dependencies]
ese-carver = "0.1"
```

```rust
let db = ese_core::EseDatabase::open("SRUDB.dat".as_ref()).unwrap();
for pair in ese_carver::detect_fragments_db(&db, expected_size) {
    if let Some(record) = ese_carver::reconstruct_fragment(&pair.prefix, &pair.suffix, expected_size) {
        // recovered record bytes
    }
}
```

## Why trust it on hostile input

`#![forbid(unsafe_code)]` (workspace), `unwrap`/`expect` denied outside tests, every offset/length bounds-checked before use, and a `cargo-fuzz` `fuzz_carver` must-not-panic target (whose first smoke pass found and fixed a real subtraction underflow).

Part of [ese-forensic](https://github.com/SecurityRonin/ese-forensic). See also [`ese-core`](https://crates.io/crates/ese-core) (the reader) and [`ese-integrity`](https://crates.io/crates/ese-integrity) (anomaly detection).

---

[Privacy Policy](https://securityronin.github.io/ese-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ese-forensic/terms/) · © 2026 Security Ronin Ltd
