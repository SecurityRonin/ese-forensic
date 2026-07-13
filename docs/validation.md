# Validation

How `ese-forensic` establishes that its ESE reader is correct, and where the
current gaps are. Claims are tiered by *who confirms them* (see the fleet
Evidence-Based Rigor discipline): tier 1 = independent third-party artifact +
answer key or real-world data; tier 2 = real engine output whose ground truth is
derivable from documented construction or an independent oracle; tier 3 = fixture
and expected answer both authored here.

## Current posture

**165 tests pass** across the workspace (`cargo test --workspace`), spanning
header/page/tag parsing, catalog decoding, record decoding, B-tree walks,
checksum verification, cursor iteration, integrity analysis, and carving.

### Tier 3 — deterministic regression + robustness (authored here)

Most unit and integration tests build fixtures with the `ese-test-fixtures`
builders and assert decoded values. These are legitimate as fast, CI-friendly
regression scaffolding and — critically — as **robustness/negative tests**:
truncated headers, short pages, lying tag counts, offsets past end-of-buffer,
non-ASCII names. The property under test ("malformed input returns an error or a
bounded result, never a panic") is a property, not a value that needs an oracle.

The real backstop for that property is the **fuzz harness**, not the tier: six
`cargo-fuzz` targets (`fuzz_ese_open`, `fuzz_catalog`, `fuzz_page`,
`fuzz_record`, `fuzz_integrity`, `fuzz_carver`), one per parsed structure, each
asserting must-not-panic. This is not theoretical — the first 100k-run smoke pass
of `fuzz_catalog` found an `attempt to add with overflow` panic (a hostile
`u32::MAX` page number fed into an unchecked `+1` in both catalog parsers), now
fixed with `saturating_add` and pinned by regression tests.

### Tier 2 — real third-party ESE databases (path-gated)

`ese-core` was developed and exercised against a corpus of **real SRUDB.dat
files from independent sources** — WithSecure Labs / Chainsaw, log2timeline /
Plaso, and Andrew Rathbun's DFIRArtifactMuseum (Windows 10/11 and Server 2022).
The `ese-integrity` and `ese-carver` integration tests that consume this corpus
are present in this repo and skip cleanly when the files are absent
(`CARGO_MANIFEST_DIR/../../tests/data/srudb/*.dat`).

That corpus currently lives in the sibling `srum-forensic` repo (large binaries,
gitignored, not redistributed here). To run these tests against ese-forensic,
place the `.dat` files under `tests/data/srudb/` at the repo root. This is a known
limitation of the extraction: the real-artifact tests are wired but the artifacts
are not yet vendored into this repo.

## Gap — future tier-1 oracle

The strongest validation an ESE reader can have is a **differential against an
independent, mature implementation** on real databases:

- **`libesedb` / `esedbexport`** (Joachim Metz) — the reference open-source ESE
  reader. A test that runs `esedbexport` on each corpus database and reconciles
  table names, column definitions, and row counts against `ese-core` output would
  promote catalog and record decoding to tier 1 (independent oracle on real data).

This differential is **not yet implemented**. Until it is, catalog/record
decoding rests on tier-2 real-data exercise plus tier-3 regression fixtures — a
value-producing path that an independent oracle *could* check, so the libesedb
differential is the priority next step for this repo's validation story.
