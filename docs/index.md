# ese-forensic

**A dependency-light Rust reader for ESE / JET Blue databases — SRUDB.dat, WebCacheV01.dat, Windows.edb, Catalog.edb, NTDS.dit.**

```toml
[dependencies]
ese-core = "0.1"
```

```rust
let db = ese_core::EseDatabase::open(std::path::Path::new("SRUDB.dat"))?;
for entry in db.catalog_entries()? {
    println!("{} -> page {}", entry.object_name, entry.table_page);
}
```

**[GitHub Repository →](https://github.com/SecurityRonin/ese-forensic)**

---

## What it does

The Extensible Storage Engine (ESE, historically "JET Blue") backs a long list of forensically interesting Windows artifacts: the SRUM database (`SRUDB.dat`), Internet Explorer / legacy Edge cache (`WebCacheV01.dat`), Windows Search (`Windows.edb`), Windows Update (`DataStore.edb`), and Active Directory (`NTDS.dit`).

`ese-core` parses the on-disk format directly — header, pages, tags, catalog, and records — with no C bindings and a tiny dependency tree (`thiserror`, `memmap2`, `serde`). It memory-maps the database read-only and never mutates the evidence.

## Crates

| Crate | Purpose |
|---|---|
| `ese-core` | Low-level ESE reader: header, pages, tags, catalog, record decoding. |
| `ese-integrity` | Structural anomaly detection — raw binary-format facts (dirty state, checksum mismatch, slack data, deleted records), not forensic conclusions. |
| `ese-carver` | Page carving and reconstruction of records fragmented across page boundaries. |
| `ese-test-fixtures` | Shared ESE fixture builders (dev-dependency only, never ships). |

## Design posture

These crates parse untrusted, attacker-influenceable binary structures. The bar is: never panic, never read out of bounds, never trust a length field. That is enforced by a panic-free lint recipe (`unsafe` denied except a single read-only mmap; `unwrap`/`expect` denied outside tests) and a `cargo-fuzz` harness with one must-not-panic target per parsed structure.

See [Validation](validation.md) for how correctness is checked.

---

[Validation](validation.md) · [Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd.
