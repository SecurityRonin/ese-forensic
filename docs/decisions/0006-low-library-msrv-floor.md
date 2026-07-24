# 6. Low CI-verified library MSRV floor (1.80), decoupled from the dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet separates the **dev toolchain** (what the repo builds/lints with) from
the **declared MSRV** (a downstream-facing promise). `ese-core`, `ese-integrity`,
and `ese-carver` are *published libraries* that other fleet crates
(`srum-forensic`, `browser-forensic`) link, so their MSRV is a compatibility
contract: raising it narrows the audience and is treated as near-breaking.

The two are declared independently in the tree:

- `rust-toolchain.toml` pins the dev toolchain to `channel = "1.96.0"`.
- `Cargo.toml [workspace.package] rust-version = "1.80"` is the promised floor.

The MSRV job is deliberately scoped away from the dev-only fixtures:
`4ffa23d ci: scope MSRV 1.80 job to published libs; mark fixtures publish=false`.

## Decision

Develop on the pinned current stable (`1.96.0`) while promising and CI-verifying
a low library MSRV of **1.80** for the three published crates. The MSRV job
covers only the published libraries; `ese-test-fixtures` (`publish = false`) is
excluded because nothing pins a library dependency against it.

## Consequences

- External and fleet consumers can link `ese-core` on a Rust as old as 1.80.
- The 1.80 floor is a CI-checked guarantee, not a claim — raise it only when the
  code genuinely needs a newer feature, not to match the 1.96 pin.
- Contributors and CI share one toolchain (1.96.0) via `rust-toolchain.toml`,
  ending fmt/clippy drift, without leaking that version into the MSRV promise.
