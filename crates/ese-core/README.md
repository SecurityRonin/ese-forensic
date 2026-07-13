[![Crates.io](https://img.shields.io/crates/v/ese-core.svg)](https://crates.io/crates/ese-core)
[![Docs.rs](https://img.shields.io/docsrs/ese-core?logo=docs.rs)](https://docs.rs/ese-core)
[![Docs](https://img.shields.io/badge/docs-securityronin.github.io-blue.svg)](https://securityronin.github.io/ese-forensic/)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://github.com/SecurityRonin/ese-forensic/blob/main/LICENSE)

[![CI](https://github.com/SecurityRonin/ese-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ese-forensic/actions/workflows/ci.yml)
[![Fuzz](https://github.com/SecurityRonin/ese-forensic/actions/workflows/fuzz.yml/badge.svg)](https://github.com/SecurityRonin/ese-forensic/actions/workflows/fuzz.yml)
[![security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-success.svg)](https://github.com/SecurityRonin/ese-forensic/blob/main/deny.toml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# ese-core

**Read ESE / JET Blue databases in Rust — SRUDB.dat, WebCacheV01.dat, Windows.edb, Catalog.edb, NTDS.dit. No C bindings, tiny dependency tree, never mutates the evidence.**

The Extensible Storage Engine backs a long list of Windows forensic artifacts, but parsing it usually means shelling out to `esedbexport` or wrestling a Python library onto the box. `ese-core` parses the on-disk format directly — header, pages, tags, catalog, records — as a static Rust library with three dependencies (`thiserror`, `memmap2`, `serde`).

```toml
[dependencies]
ese-core = "0.2"
```

```rust
use ese_core::EseDatabase;

let db = EseDatabase::open(std::path::Path::new("SRUDB.dat"))?;
for entry in db.catalog_entries()? {
    println!("{:<32} root page {}", entry.object_name, entry.table_page);
}
for row in db.table_records("SruDbIdMapTable")? {
    println!("{row:?}");
}
# Ok::<(), ese_core::EseError>(())
```

---

## The crates

| Crate | What it does |
|---|---|
| **`ese-core`** | Low-level reader: header, pages, tag arrays, catalog, record decoding, B-tree/leaf-page walks, checksum verification. Read-only mmap. |
| **`ese-integrity`** | Structural anomaly detection — dirty shutdown, page checksum mismatch, broken B-tree links, slack-region data, orphaned catalog entries, deleted records. Reports raw binary-format facts, not forensic conclusions. |
| **`ese-carver`** | Carves records fragmented across page boundaries and reconstructs them from prefix/suffix tag pairs. |

## Why trust it on hostile input

ESE files are attacker-influenceable binary evidence, so the crates are built to never panic, never read out of bounds, and never trust a length field:

- **`unsafe` denied** across the workspace, with a single justified exception: the read-only `memmap2` map in `ese-core`.
- **`unwrap`/`expect` denied** outside tests; every length, offset, and count from the file is bounds-checked before use.
- **`cargo-fuzz` harness**, one must-not-panic target per parsed structure (`fuzz_ese_open`, `fuzz_catalog`, `fuzz_page`, `fuzz_record`, `fuzz_integrity`, `fuzz_carver`). The first smoke pass found and fixed a real page-number overflow. See [validation](https://github.com/SecurityRonin/ese-forensic/blob/main/docs/validation.md).

## Install

```bash
cargo add ese-core            # the reader
cargo add ese-integrity       # + anomaly detection
cargo add ese-carver          # + fragment carving
```

## Status

`ese-core` is extracted from and shared with [`srum-forensic`](https://github.com/SecurityRonin/srum-forensic); [`browser-forensic`](https://github.com/SecurityRonin/browser-forensic) and other consumers reuse it. Real-database validation currently rests on a third-party SRUDB.dat corpus exercised in the sibling repos; validated against a `libesedb`/`esedbexport` differential on a real 32 KB-page `WebCacheV01.dat` (37 containers / 360 records reconciled) — see [details](https://github.com/SecurityRonin/ese-forensic/blob/main/docs/validation.md).

---

[Privacy Policy](https://securityronin.github.io/ese-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ese-forensic/terms/) · © 2026 Security Ronin Ltd
