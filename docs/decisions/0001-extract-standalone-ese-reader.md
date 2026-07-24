# 1. Extract a standalone ESE reader from srum-forensic

Date: 2026-07-24
Status: Accepted

## Context

The Extensible Storage Engine (ESE, "JET Blue") is the on-disk database format
behind a long list of Windows forensic artifacts: `SRUDB.dat` (SRUM),
`WebCacheV01.dat` (IE/Edge history and cache), `Windows.edb` (Search),
`Catalog.edb`, and Active Directory's `NTDS.dit`. Several fleet analyzers need
to read ESE, not just one. `srum-forensic` already carried an ESE parser as an
internal module, but that made the format reader a private detail of the SRUM
analyzer — invisible to `browser-forensic` (WebCacheV01) and any future ESE
consumer, and impossible to depend on, version, or fuzz independently.

The first commit of this repository is literally the extraction:
`e471dcc feat: extract standalone ese-forensic reader from srum-forensic`.
The README "Status" section records the shared-ownership relationship:
`ese-core` "is extracted from and shared with `srum-forensic`;
`browser-forensic` and other consumers reuse it."

This follows two fleet rules from `ronin-issen/CLAUDE.md`: PARSER-layer crates
own their format knowledge as reusable libraries (the layer architecture), and
"prefer our own crates" — a single audited ESE reader beats an internal copy
per consumer.

## Decision

Publish ESE format handling as a standalone, independently versioned workspace
(`ese-forensic`) with `ese-core` as the reusable reader crate. `srum-forensic`,
`browser-forensic`, and later ESE consumers depend on the published `ese-core`
rather than each carrying their own parser. The repo lives in the PARSER layer:
it accepts a `Path` (or bytes) and depends downward only on `forensicnomicon`
(KNOWLEDGE) — never on a container or filesystem crate.

## Consequences

- One ESE parser is fuzzed, validated, and hardened once; every consumer
  inherits the fixes (e.g. the fuzz-found overflow bugs in ADR 0005).
- The reader is now versioned on crates.io (`ese-core 0.2.1`), so consumers
  pin a registry version instead of a path into a sibling checkout.
- Extraction carried over SRUM-specific residue that a generic ESE crate should
  not own — most visibly the `SRUM-ESE-*` finding codes in `ese-integrity`
  (see ADR 0007). That is documented debt, not a fresh design choice.
- The real-database validation corpus (`SRUDB.dat` samples) still lives in the
  `srum-forensic` repo; `ese-forensic`'s real-artifact tests are wired but the
  artifacts are not yet vendored here (see `docs/validation.md`).
