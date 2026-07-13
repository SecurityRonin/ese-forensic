#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for ese-carver fragment detection and reconstruction.
//!
//! Tests [`ese_carver::detect_fragments`] and [`ese_carver::reconstruct_fragment`].

mod fixtures;

use ese_carver::{detect_fragments, reconstruct_fragment};

// ── detect_fragments ─────────────────────────────────────────────────────────

#[test]
fn detect_fragments_empty_for_complete_pages() {
    // Three complete records of 12 bytes each — no page-boundary splits.
    let record = vec![0xABu8; 12];
    let pages = fixtures::make_flat_complete(&[record.clone(), record.clone(), record]);
    let pairs = detect_fragments(&pages, fixtures::PAGE_SIZE, 12);
    assert!(
        pairs.is_empty(),
        "complete records must produce no FragmentPair, got: {pairs:?}"
    );
}

#[test]
fn detect_fragments_finds_pair_when_split_across_boundary() {
    // Record of 20 bytes split: 12-byte prefix on page 1, 8-byte suffix on page 2.
    let prefix = vec![0xAAu8; 12];
    let suffix = vec![0xBBu8; 8];
    let expected_size = prefix.len() + suffix.len(); // 20
    let pages = fixtures::make_flat_split(&prefix, &suffix);
    let pairs = detect_fragments(&pages, fixtures::PAGE_SIZE, expected_size);
    assert_eq!(
        pairs.len(),
        1,
        "one split must produce exactly one FragmentPair"
    );
    let pair = &pairs[0];
    assert_eq!(pair.page_a, 1, "prefix lives on page 1");
    assert_eq!(pair.page_b, 2, "suffix lives on page 2");
    assert_eq!(pair.prefix_len, 12);
    assert_eq!(pair.suffix_len, 8);
}

#[test]
fn detect_fragments_ignores_split_when_sizes_do_not_match_expected() {
    // Same split pages but caller supplies the wrong expected_size — no match.
    let prefix = vec![0xCCu8; 10];
    let suffix = vec![0xDDu8; 10];
    let pages = fixtures::make_flat_split(&prefix, &suffix);
    // expected_size = 30, but prefix+suffix = 20 — should not match
    let pairs = detect_fragments(&pages, fixtures::PAGE_SIZE, 30);
    assert!(
        pairs.is_empty(),
        "size mismatch must produce no FragmentPair, got: {pairs:?}"
    );
}

// ── detect_fragments_db ──────────────────────────────────────────────────────

#[test]
fn detect_fragments_db_finds_split_via_ese_database() {
    use std::io::Write as _;
    let prefix = vec![0xAAu8; 12];
    let suffix = vec![0xBBu8; 8];
    let pages = fixtures::make_flat_split(&prefix, &suffix);
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pages).unwrap();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let pairs = ese_carver::detect_fragments_db(&db, 20);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].prefix_len, 12);
    assert_eq!(pairs[0].suffix_len, 8);
}

// ── detect_fragments_db: real fixture smoke tests ────────────────────────────

fn real_fixture(path: &str) -> Option<ese_core::EseDatabase> {
    let p = std::path::Path::new(path);
    if !p.exists() {
        return None;
    }
    Some(ese_core::EseDatabase::open(p).expect("open real SRUDB"))
}

const CHAINSAW: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/chainsaw_SRUDB.dat"
);
const RATHBUNVM_WIN10: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_rathbunvm_win10_SRUDB.dat"
);
const APTVM_CLEAN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_aptvm_server2022_clean_SRUDB.dat"
);

/// Real ESE records are larger than 32 bytes; `detect_fragments_db(32)` must
/// return 0 — confirming no false positives at the synthetic fixture size.
#[test]
fn chainsaw_has_no_fragments_at_size_32() {
    let Some(db) = real_fixture(CHAINSAW) else {
        return;
    };
    let pairs = ese_carver::detect_fragments_db(&db, 32);
    assert_eq!(
        pairs.len(),
        0,
        "chainsaw: real ESE records do not split at exactly 32 bytes"
    );
}

#[test]
fn rathbunvm_win10_has_no_fragments_at_size_32() {
    let Some(db) = real_fixture(RATHBUNVM_WIN10) else {
        return;
    };
    let pairs = ese_carver::detect_fragments_db(&db, 32);
    assert_eq!(
        pairs.len(),
        0,
        "rathbunvm_win10: real ESE records do not split at exactly 32 bytes"
    );
}

#[test]
fn aptvm_clean_has_no_fragments_at_size_32() {
    let Some(db) = real_fixture(APTVM_CLEAN) else {
        return;
    };
    let pairs = ese_carver::detect_fragments_db(&db, 32);
    assert_eq!(
        pairs.len(),
        0,
        "aptvm_clean: fresh Server 2022 must not produce carver false positives"
    );
}

// ── reconstruct_fragment ─────────────────────────────────────────────────────

#[test]
fn reconstruct_returns_none_when_lengths_do_not_match_expected() {
    let prefix = vec![0x01u8; 4];
    let suffix = vec![0x02u8; 4];
    // prefix+suffix = 8, but expected = 12
    let result = reconstruct_fragment(&prefix, &suffix, 12);
    assert!(result.is_none(), "length mismatch must return None");
}

#[test]
fn reconstruct_returns_stitched_bytes_when_lengths_match() {
    let prefix = vec![0xAAu8; 6];
    let suffix = vec![0xBBu8; 6];
    let expected_size = 12;
    let result = reconstruct_fragment(&prefix, &suffix, expected_size);
    assert!(result.is_some(), "matching lengths must return Some");
    let stitched = result.unwrap();
    assert_eq!(stitched.len(), expected_size);
    assert_eq!(&stitched[..6], &prefix[..]);
    assert_eq!(&stitched[6..], &suffix[..]);
}
