# 3. Crate naming: `ese-core` reader, `ese_core` import path, unpublished fixtures

Date: 2026-07-24
Status: Accepted

## Context

The fleet Crate naming grammar (`ronin-issen/CLAUDE.md`) requires that a crate
name be self-describing when read *bare* on crates.io, and that a reader publish
as `<x>-core`. The bare word `ese` is a short, generic token; a crate simply
named `ese` would not claim a clear namespace, and the grammar's collision rule
keeps a distinctive import path rather than hijacking a popular bare name.

The workspace does not override `[lib] name`, so the reader's import path is the
default `ese_core`, matching the README example:

```rust
use ese_core::EseDatabase;
```

`ese-test-fixtures` builds ESE byte layouts used only by tests across the three
published crates. It has no runtime role and must never reach crates.io.

Whether the bare `ese` name was avoided because of a specific third-party
collision, or purely to satisfy the self-describing rule, is not stated in the
commit history.

## Decision

1. Publish the reader as **`ese-core`** with the default **`ese_core`** import
   path; the analyzer as **`ese-integrity`** and the recovery crate as
   **`ese-carver`**, one role per suffix per the naming grammar.
2. Keep **`ese-test-fixtures`** as a dev-only crate with `publish = false`
   (`crates/ese-test-fixtures/Cargo.toml`), reached by the other members only
   through `[dev-dependencies]`.

## Consequences

- Consumers write `use ese_core::...`; no fleet crate claims the bare `ese`
  namespace on crates.io.
- The dev-only fixtures never ship, so a `cargo publish` of any of the three
  library crates carries no test scaffolding.
- **Unrecovered rationale:** the commit history does not record whether the
  `ese`→`ese-core` choice was driven by a concrete crates.io collision or by the
  self-describing naming rule alone. Rationale reconstructed from structure and
  the naming grammar; original intent not recovered in available history.
