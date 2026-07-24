# 2. Split the suite into core / integrity / carver / test-fixtures

Date: 2026-07-24
Status: Accepted

## Context

An ESE forensic capability is three separable jobs: (1) read the format
correctly, (2) detect structural anomalies in it, and (3) recover records the
format has fragmented or deleted. Folding all three into one crate would force
every consumer that only needs to *read* a database to also pull the anomaly
model (`forensicnomicon`) and the carver, and would blur the forensic boundary
between "raw facts a reader produces" and "anomalies an analyzer judges."

The fleet's Crate-structure standard (`ronin-issen/CLAUDE.md`) prescribes a
reader/analyzer split and, for a suite decomposed by concern, role suffixes:
`-core` (reader), `-integrity` (tamper/corruption analyzer slot), `-carve`
(recovery). The workspace `Cargo.toml` realizes exactly this:

```
members = [
  "crates/ese-core",         # reader
  "crates/ese-integrity",    # structural anomaly analyzer
  "crates/ese-carver",       # fragmented-record recovery
  "crates/ese-test-fixtures" # dev-only fixture builders
]
```

## Decision

Decompose the repo into four crates by concern:

1. **`ese-core`** — the low-level reader: header, pages, tag arrays, catalog,
   record decoding, B-tree/leaf walks, checksum verification. Produces raw
   parsed structures and no findings. Depends only on `thiserror`, `memmap2`,
   `serde`.
2. **`ese-integrity`** — structural anomaly detection over an open
   `EseDatabase`, emitting `forensicnomicon::report` findings (ADR 0007).
   Depends down onto `ese-core` + `forensicnomicon`.
3. **`ese-carver`** — page carving and fragmented/deleted record
   reconstruction over `ese-core` structures. Depends down onto `ese-core`.
4. **`ese-test-fixtures`** — shared ESE byte-builders used only as a
   `dev-dependency`; `publish = false` (ADR 0006).

The dependency arrow always points down: analyzers and the carver depend on the
reader; the reader depends on nothing in the suite.

## Consequences

- A consumer that only reads ESE (e.g. `browser-forensic` for WebCacheV01)
  depends on `ese-core` alone — no `forensicnomicon`, no carver in its tree.
- Each crate versions independently (`ese-core 0.2.1`, `ese-integrity 0.3.2`,
  `ese-carver 0.1.2`), so a reader fix ships without forcing an analyzer bump.
- The forensic epistemology is enforced structurally: `ese-core` cannot emit a
  "finding" because it does not depend on the report model; only `ese-integrity`
  can, keeping "raw fact" and "graded anomaly" in different crates.
- `ese-integrity` currently consumes `ese-core`'s public reader API. Where an
  audit needs to see below that API (slack bytes, deleted/overwritten records
  the reader would normalize), the fleet standard permits `-integrity` to parse
  raw structure directly; that lower-level path is available but not yet a
  formal seam here.
