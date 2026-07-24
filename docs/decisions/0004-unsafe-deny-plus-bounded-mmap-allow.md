# 4. `unsafe_code = deny` with one bounded read-only mmap exception

Date: 2026-07-24
Status: Accepted

## Context

ESE files are attacker-influenceable binary evidence, so the fleet default for a
parser is `unsafe_code = "forbid"` — a provable "no place a crafted input can
corrupt memory." But `ese-core` maps the database read-only with `memmap2` for
zero-copy access to multi-gigabyte files (`SRUDB.dat`, `NTDS.dit`), and
`Mmap::map` is `unsafe` by construction. `forbid` cannot be locally overridden,
so a single legitimate mmap site would be impossible under `forbid`.

The fleet's unsafe-exception law and the Paranoid Gatekeeper standard cover this
exact case: downgrade to `deny` and carry a bounded, annotated per-site
`#[allow(unsafe_code)]`, stating the benefit, the rejected alternative, and the
invariant. The workspace lints already encode the reasoning:

```toml
# ese-forensic/Cargo.toml
[workspace.lints.rust]
# ... unsafe-free except the single read-only mmap in ese-core ...
unsafe_code = "deny"
```

and the one site is annotated in `crates/ese-core/src/database.rs:129`:

```rust
// SAFETY: the mapped file is read-only forensic evidence; we never write ...
#[allow(unsafe_code)]
let mmap = unsafe { Mmap::map(&file) }?;
```

## Decision

Set `unsafe_code = "deny"` workspace-wide and permit exactly **one** bounded
`#[allow(unsafe_code)]`: the read-only `memmap2::Mmap::map` in `ese-core`. Every
other `unsafe` remains a hard compile error. The mmap is read-only; the reader
never writes through it, preserving the "never mutate the evidence" property.

## Consequences

- `rg 'allow(unsafe_code)'` is the complete audit surface — one pure-Rust,
  no-C site, the categorically smaller class of unsafe per the fleet law.
- Large databases are read with bounded memory and no full-file copy.
- The suite cannot wear an "unsafe-forbidden" badge; the README correctly states
  "`unsafe` denied ... with a single justified exception" and the READMEs omit
  the unsafe-forbidden badge, consistent with the fleet badge rule for
  `deny + allow` crates.
- The exception is pure-Rust with no FFI, so it does not compromise the
  no-C-bindings posture the README advertises.
