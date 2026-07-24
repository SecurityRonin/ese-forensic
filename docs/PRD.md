# ese-forensic — Purpose & Scope

> Library-tier intent document. `ese-forensic` ships no binary an examiner runs;
> it is a suite of Rust libraries that other fleet crates link. This is the
> concise Purpose & Scope the fleet standard prescribes for a library repo, not a
> full product PRD.

## What it is

`ese-forensic` reads Microsoft's **Extensible Storage Engine** (ESE / "JET Blue")
database format directly in pure Rust — no C bindings, no shelling out to
`esedbexport`, and it never mutates the evidence (read-only mmap). ESE backs a
long list of Windows forensic artifacts, so a correct, hardened, reusable ESE
reader is infrastructure the fleet needs once and shares everywhere.

The repo is three published library crates plus a dev-only fixture crate:

| Crate | Role | Depends on |
|---|---|---|
| **`ese-core`** | Low-level reader: header, pages, tag arrays, catalog, record decoding, B-tree/leaf walks, checksum verification. Read-only mmap; produces raw structures, no findings. | `thiserror`, `memmap2`, `serde` |
| **`ese-integrity`** | Structural anomaly detection over an open database, emitted as `forensicnomicon::report` findings — raw binary-format facts, not forensic conclusions. | `ese-core`, `forensicnomicon` |
| **`ese-carver`** | Page carving and reconstruction of records fragmented across page boundaries. | `ese-core` |
| **`ese-test-fixtures`** | Shared ESE byte-builders for tests. `publish = false`. | `ese-core` (dev only) |

## Who links it

- **`srum-forensic`** — the SRUM analyzer; `ese-core` was extracted from it and
  is shared back (ADR 0001).
- **`browser-forensic`** — reads `WebCacheV01.dat` (IE/Edge) via `ese-core`.
- **Future ESE consumers** — `Windows.edb` (Search), `Catalog.edb`,
  `NTDS.dit` (Active Directory) all use the same on-disk format.

Consumers that only need to *read* a database link `ese-core` alone; the
anomaly model and carver stay out of their dependency tree (ADR 0002).

## Artifact family

ESE / JET Blue databases, all little-endian, page sizes 4096 / 8192 / 16384 /
32768, magic `0x89ABCDEF` at file offset 4, with legacy XOR and Vista+ ECC page
checksums. Named targets: `SRUDB.dat`, `WebCacheV01.dat`, `Windows.edb`,
`Catalog.edb`, `NTDS.dit`.

## Scope

- Parse the ESE on-disk format: header, pages, tag arrays, catalog
  (`MSysObjects`), fixed/variable/tagged columns, B-tree and leaf-page walks,
  cursor iteration over table records.
- Verify page checksums (legacy XOR and Vista+ ECC) as raw facts.
- Detect structural anomalies (dirty shutdown, checksum mismatch, broken B-tree
  links, slack-region data, orphaned/missing catalog entries, deleted records,
  truncation, timestamp skew) and report them in the shared finding model.
- Carve and reconstruct records fragmented across page boundaries.
- Meet the Paranoid Gatekeeper bar: never panic, never read out of bounds, never
  trust a length field; fuzzed one target per parsed structure (ADR 0005).

## Non-goals

- **No transaction-log replay.** `ese-forensic` reads the `.dat`/`.edb`/`.dit`
  as it sits on disk; it does not apply `.log`/checkpoint files. Dirty-shutdown
  state is reported as an observation, not repaired.
- **No writing, ever.** The mmap is read-only; there are no mutation paths. The
  carver and any reconstruction emit derived output, never touching the source.
- **No forensic conclusions.** Anomalies are raw binary facts; inference and
  correlation belong to the ORCHESTRATION layer (Issen / a triage layer), not to
  these libraries (ADR 0007).
- **No front-end.** No CLI, GUI, or MCP server lives here; user-facing tooling is
  a separate concern. This keeps the repo firmly library-tier.
- **No artifact-semantic decoding.** Turning a decoded SRUM/WebCache row into a
  user-activity event is the consuming analyzer's job, not `ese-core`'s.

## Validation approach

Correctness is tiered by *who confirms it* (see `docs/validation.md`):

- **Tier 3** — deterministic regression and robustness tests built with
  `ese-test-fixtures` (~165 workspace tests), plus fuzz-found regression pins.
- **Tier 2** — real `SRUDB.dat` corpora exercised in the sibling `srum-forensic`
  repo (the corpus is not yet vendored into this repo).
- **Tier 1 (planned)** — a **`libesedb` / `esedbexport` differential** over real
  databases, reconciling table names, column definitions, and row counts. This
  is the priority next step and is not yet implemented; the validation doc states
  the gap honestly rather than overclaiming.
