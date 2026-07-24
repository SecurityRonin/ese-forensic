# 5. Panic-free bounded reads + one fuzz target per parsed ESE structure

Date: 2026-07-24
Status: Accepted

## Context

Every field in an ESE file — page sizes, tag offsets, record counts,
`pgnoFDP` catalog pointers — is attacker-controllable. A reader that trusts a
length field, indexes without a bounds check, or unwraps an `Option` derived
from file bytes turns a malformed database into a panic (denial of service) or,
worse, silent wrong output. The fleet Paranoid Gatekeeper standard mandates:
never panic, never read out of bounds, never trust a length field, backed by
per-structure fuzzing.

The evidence that this bar is real, not aspirational, is the git history: the
first fuzz smoke pass found and fixed concrete overflow/underflow bugs.

- `fbdd270 feat: add cargo-fuzz harness — one target per parsed ESE structure`
- `0150165 test: RED — catalog pgnoFDP+1 overflows on u32::MAX (fuzz-found)` →
  `ee497c0 fix: GREEN — saturate catalog pgnoFDP+1 to prevent overflow panic`
- `577643 test: RED — carver tag walk underflows on lying tag_count` →
  `8f8a9ad fix: GREEN — bound carver tag walk against lying tag_count`
- `b9a1684 test: RED — large-page tag mask truncates offsets >8191` →
  `f23e3f6 fix: GREEN — decode large-page (16K/32K) tags with extended header`

The `fuzz/fuzz_targets/` directory carries one target per parsed structure:
`fuzz_ese_open`, `fuzz_catalog`, `fuzz_page`, `fuzz_record`, `fuzz_integrity`,
`fuzz_carver`. The workspace lints deny the panic operators outside tests:

```toml
unwrap_used = { level = "deny", priority = 0 }
expect_used = { level = "deny", priority = 0 }
```

## Decision

1. Deny `unwrap`/`expect` in production (allowed in tests via `clippy.toml`
   `allow-unwrap-in-tests`); bounds-check every offset, length, and count read
   from the file before use; saturate/`try_from` arithmetic on file-derived
   page numbers.
2. Maintain a `cargo-fuzz` harness with **one must-not-panic target per parsed
   structure**, wired into `fuzz.yml`, and drive every fuzz-found bug through a
   RED (failing regression test) → GREEN (fix) commit pair.

## Consequences

- A crafted ESE database cannot panic the reader, the integrity analyzer, or the
  carver; malformed input degrades to a typed `EseError` or a skipped page.
- Fuzz-found regressions are pinned by committed tests, so a future refactor
  cannot silently reintroduce a fixed overflow.
- **Deviation from the fleet `safe-read` standard, stated honestly:** `ese-core`
  performs its bounds-checked integer reads with in-line `from_le_bytes` over
  explicitly length-checked slices rather than routing through the fleet
  `safe-read` crate. This predates / sidesteps the "never hand-roll a per-crate
  reader" rule; migrating the fixed-width reads to `safe-read` is open debt.
  Rationale for the original hand-rolled choice not recovered in available
  history (the code was extracted from `srum-forensic`; see ADR 0001).
