#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Robustness tests for [`ese_integrity::EseIntegrity`] unified analyser.
//!
//! These tests verify that `EseIntegrity` correctly detects structural problems
//! in crafted malformed byte buffers — cases where `EseDatabase::open` would
//! either panic, fail, or silently accept corrupt data.

mod fixtures;

use ese_integrity::{anomalies_at_least, EseIntegrity, EseStructuralAnomaly, Severity};

// ── check_layout / TruncatedDatabase ────────────────────────────────────────

#[test]
fn empty_buffer_returns_truncated_database() {
    let anomalies = EseIntegrity::new(&[]).analyse();
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::TruncatedDatabase { .. }));
    assert!(found, "empty buffer must produce TruncatedDatabase");
}

#[test]
fn undersized_buffer_returns_truncated_database() {
    // A buffer with a valid header page but no shadow page (< 8192 bytes).
    let mut buf = vec![0u8; 4096];
    // Write ESE magic so header looks valid
    buf[4..8].copy_from_slice(&0x89AB_CDEF_u32.to_le_bytes());
    buf[236..240].copy_from_slice(&4096_u32.to_le_bytes()); // page_size = 4096

    let anomalies = EseIntegrity::new(&buf).analyse();
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::TruncatedDatabase { .. }));
    assert!(found, "buffer < 8192 bytes must produce TruncatedDatabase");
}

#[test]
fn truncated_database_has_critical_severity() {
    let anomalies = EseIntegrity::new(&[]).analyse();
    let criticals: Vec<_> = anomalies_at_least(&anomalies, Severity::Critical);
    assert!(
        !criticals.is_empty(),
        "TruncatedDatabase must produce at least one Critical anomaly"
    );
}

// ── check_pages / PageChecksumMismatch ──────────────────────────────────────

/// Build a raw two-page ESE buffer where page 1 has a non-zero, incorrect
/// XOR checksum. The XOR checksum at offset 0 should equal the XOR of all
/// subsequent 4-byte words; here it is deliberately set to 0xDEADBEEF while
/// all other bytes are zero, so the computed checksum won't match.
fn make_buf_with_bad_page_checksum() -> Vec<u8> {
    let page_size = 4096_usize;
    let mut buf = vec![0u8; page_size * 3]; // header + 2 data pages

    // Header page (page 0): valid ESE magic + page_size
    buf[4..8].copy_from_slice(&0x89AB_CDEF_u32.to_le_bytes());
    buf[236..240].copy_from_slice(&(page_size as u32).to_le_bytes());

    // Page 1 (shadow header / first data page): write a bad checksum at offset 0.
    // All other bytes in page 1 are 0, so the correct XOR checksum is
    // 0x89ABCDEF (seed only). We store 0xDEADBEEF instead → mismatch.
    let p1_start = page_size;
    buf[p1_start..p1_start + 4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());

    buf
}

#[test]
fn page_with_bad_checksum_returns_checksum_mismatch() {
    let buf = make_buf_with_bad_page_checksum();
    let anomalies = EseIntegrity::new(&buf).analyse();
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::PageChecksumMismatch { .. }));
    assert!(
        found,
        "page with bad XOR checksum must produce PageChecksumMismatch"
    );
}

// ── clean minimal database → no anomalies ────────────────────────────────────

#[test]
fn minimal_valid_database_has_no_anomalies() {
    // EseFileBuilder creates pages with all-zero checksums (unchecked).
    // EseIntegrity skips checksum verification when the stored checksum is 0.
    // We include one data page so the file meets the 8192-byte dual-shadow minimum.
    use ese_test_fixtures::{EseFileBuilder, PageBuilder, PAGE_SIZE};
    use std::io::Read as _;
    let data_page = PageBuilder::new(PAGE_SIZE).leaf().build();
    let tmp = EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write();
    let mut file = std::fs::File::open(tmp.path()).expect("open");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read");
    assert!(
        bytes.len() >= 8192,
        "fixture must be at least 8192 bytes (got {})",
        bytes.len()
    );

    let anomalies = EseIntegrity::new(&bytes).analyse();
    let errors_or_above: Vec<_> = anomalies_at_least(&anomalies, Severity::High);
    assert!(
        errors_or_above.is_empty(),
        "clean minimal database must produce no Error/Critical anomalies; got: {errors_or_above:?}"
    );
}

// ── ECC checksum fallback (Phase 18-C item 4) ────────────────────────────────
//
// Vista+ ESE pages store an 8-byte checksum header:
//   bytes 0-3: XOR of all 4-byte words from offset 8+, seeded with 0x89ABCDEF
//   bytes 4-7: column-parity ECC of all 4-byte words from offset 8+
//
// The format-detection heuristic: bytes 4-7 zero → legacy XOR; non-zero → Vista+ ECC.
// check_pages() must handle both formats via ese_core::verify_page_checksum().

const XOR_SEED: u32 = 0x89AB_CDEF;

fn compute_xor_of_slice(data: &[u8]) -> u32 {
    let mut csum = XOR_SEED;
    for chunk in data.chunks_exact(4) {
        csum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    csum
}

fn compute_column_parity_ecc(data: &[u8]) -> u32 {
    let mut ecc: u32 = 0;
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        ecc ^= word.rotate_left((i % 32) as u32);
    }
    ecc
}

/// Build a 3-page ESE buffer where page 1 carries a Vista+ ECC checksum that is
/// VALID. Bytes 4-7 are non-zero (ECC field), so the legacy XOR-only algorithm
/// produces a false mismatch. The ECC-aware path must accept the page as clean.
fn make_buf_with_valid_ecc_page() -> Vec<u8> {
    let page_size = 4096_usize;
    let mut buf = vec![0u8; page_size * 3];

    // Header page (page 0): ESE magic + page_size
    buf[4..8].copy_from_slice(&0x89AB_CDEF_u32.to_le_bytes());
    buf[236..240].copy_from_slice(&(page_size as u32).to_le_bytes());

    // Page 1: Vista+ ECC format.
    // Place some non-zero data in the body (offset 8+); bytes 0-7 are the checksum header.
    let p1 = page_size;
    buf[p1 + 8] = 0xAB; // non-zero data in the body
    buf[p1 + 12] = 0xCD;

    let body = &buf[p1 + 8..p1 + page_size].to_vec();
    let stored_xor = compute_xor_of_slice(body);
    let stored_ecc = compute_column_parity_ecc(body);

    buf[p1..p1 + 4].copy_from_slice(&stored_xor.to_le_bytes()); // XOR at offset 0
    buf[p1 + 4..p1 + 8].copy_from_slice(&stored_ecc.to_le_bytes()); // ECC at offset 4

    buf
}

/// Build a 3-page ESE buffer where page 1 is a Vista+ ECC page with a TAMPERED
/// data byte — the stored checksum no longer matches the body. `check_pages()` must
/// detect this and emit `PageChecksumMismatch`.
fn make_buf_with_tampered_ecc_page() -> Vec<u8> {
    let mut buf = make_buf_with_valid_ecc_page();
    let page_size = 4096_usize;
    // Flip one body byte without updating the stored checksum.
    buf[page_size + 8] ^= 0xFF;
    buf
}

#[test]
fn valid_ecc_page_does_not_produce_false_positive() {
    // A Vista+ page with a correct ECC checksum must NOT be flagged.
    // The old XOR-only code in check_pages() would compute XOR over bytes 4+
    // (including the ECC field), producing a wrong comparison → false positive.
    let buf = make_buf_with_valid_ecc_page();
    let anomalies = EseIntegrity::new(&buf).analyse();
    let false_pos = anomalies.iter().any(|a| {
        matches!(
            a,
            EseStructuralAnomaly::PageChecksumMismatch { page_number: 1, .. }
        )
    });
    assert!(
        !false_pos,
        "valid ECC page must NOT produce PageChecksumMismatch; got: {anomalies:?}"
    );
}

#[test]
fn tampered_ecc_page_produces_checksum_mismatch() {
    // A Vista+ page with a corrupted body (checksum no longer matches) MUST be flagged.
    let buf = make_buf_with_tampered_ecc_page();
    let anomalies = EseIntegrity::new(&buf).analyse();
    let detected = anomalies.iter().any(|a| {
        matches!(
            a,
            EseStructuralAnomaly::PageChecksumMismatch { page_number: 1, .. }
        )
    });
    assert!(
        detected,
        "tampered ECC page must produce PageChecksumMismatch; got: {anomalies:?}"
    );
}
