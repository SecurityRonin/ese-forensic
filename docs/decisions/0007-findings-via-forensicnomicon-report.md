# 7. Anomalies as `forensicnomicon::report` observations, never conclusions

Date: 2026-07-24
Status: Accepted

## Context

`ese-integrity` reports structural problems it finds in an ESE database — dirty
shutdown, page checksum mismatch, broken B-tree links, slack-region data,
orphaned catalog entries, deleted records, truncation, timestamp skew. Two fleet
rules govern how it says so:

1. **One reporting vocabulary.** Every analyzer emits the shared
   `forensicnomicon::report` model so ORCHESTRATION (Issen) renders findings
   uniformly instead of N bespoke `XxxAnalysis` types. The producer keeps its
   typed `AnomalyKind` and converts via `impl Observation`.
2. **Findings are observations, never legal conclusions** — "raw binary-format
   facts, not forensic conclusions"; the correlation layer draws inferences.

The code realizes both: `EseStructuralAnomaly` is the typed domain enum, and

```rust
// crates/ese-integrity/src/lib.rs:633
impl forensicnomicon::report::Observation for EseStructuralAnomaly {
    fn severity(&self) -> Option<Severity> { ... }
    fn code(&self) -> &'static str { ... }
    fn note(&self) -> String { ... }
}
```

Severities use the canonical 5-level scale re-exported from
`forensicnomicon::report::Severity`.

## Decision

Keep the typed `EseStructuralAnomaly` enum as the domain knowledge and expose
each variant to the fleet by implementing `forensicnomicon::report::Observation`
(published SCREAMING-KEBAB `code`, canonical `Severity`, plain-language `note`).
The crate's doc comment binds the epistemic contract: it produces parsing-level
observations, and forensic interpretation belongs to the correlation layer.

## Consequences

- ESE anomalies aggregate into the same `Report` as every other fleet analyzer;
  a GUI or Issen renders them without ESE-specific code.
- The observation-not-conclusion boundary is documented at the type level, so an
  anomaly reads as "checksum mismatch at page N," never "the database was
  tampered with."
- **Naming debt carried from the extraction (ADR 0001):** the finding codes are
  prefixed `SRUM-ESE-*` (e.g. `SRUM-ESE-DELETED-RECORD-PRESENT`) even though the
  crate is a generic ESE analyzer, not SRUM-specific. `code` is a published
  contract that must not change once shipped, so re-scoping these to a neutral
  `ESE-*` prefix is a deliberate future migration (new codes, not a rename), not
  a silent edit. Rationale for the SRUM prefix is the srum-forensic origin, not a
  design intent for the standalone crate.
