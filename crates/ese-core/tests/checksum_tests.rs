#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Tests for `verify_page_checksum` — Phase 1 stories 13–16.

use ese_core::{verify_page_checksum, ChecksumResult, PAGE_SIZE};

/// Build a page buffer with the legacy XOR checksum correctly stored at offset 0.
///
/// Seed = `0x89AB_CDEF`; checksum XORs all 4-byte words from offset 4 onward.
/// Payload is placed at offset 8+ so bytes 4-7 remain zero — this is required
/// for the format-detection heuristic (zero bytes 4-7 ⟹ legacy, non-zero ⟹ ECC).
fn make_page_with_correct_xor(payload: &[u8]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    // Write payload starting at offset 8; bytes 4-7 stay zero (legacy indicator).
    let len = payload.len().min(PAGE_SIZE - 8);
    page[8..8 + len].copy_from_slice(&payload[..len]);
    // Compute XOR checksum over bytes 4+ (includes the zero bytes 4-7).
    let seed: u32 = 0x89AB_CDEF;
    let mut csum = seed;
    for chunk in page[4..].chunks_exact(4) {
        csum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    page[0..4].copy_from_slice(&csum.to_le_bytes());
    page
}

/// Build a page with a deliberately wrong XOR checksum.
///
/// Data is placed at offset 8+ (bytes 4-7 remain zero) so the heuristic
/// correctly identifies this as legacy format before returning the mismatch.
fn make_page_with_wrong_xor() -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    page[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // wrong stored checksum
    page[8] = 0x01; // non-zero data at offset 8+; bytes 4-7 stay zero (legacy indicator)
    page
}

// ── story 13 / 14: legacy XOR ────────────────────────────────────────────────

#[test]
fn verify_page_checksum_valid_for_correct_legacy_xor() {
    let page = make_page_with_correct_xor(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let result = verify_page_checksum(&page, 1);
    assert!(
        matches!(result, ChecksumResult::Valid),
        "correctly-computed XOR must return Valid, got {result:?}"
    );
}

#[test]
fn verify_page_checksum_mismatch_for_wrong_xor() {
    let page = make_page_with_wrong_xor();
    let result = verify_page_checksum(&page, 2);
    assert!(
        matches!(result, ChecksumResult::LegacyXorMismatch { .. }),
        "wrong XOR must return LegacyXorMismatch, got {result:?}"
    );
}

#[test]
fn verify_page_checksum_mismatch_carries_values() {
    let page = make_page_with_wrong_xor();
    let result = verify_page_checksum(&page, 3);
    if let ChecksumResult::LegacyXorMismatch { stored, computed } = result {
        assert_eq!(stored, 0xDEAD_BEEF);
        assert_ne!(computed, stored, "computed must differ from stored");
    } else {
        panic!("expected LegacyXorMismatch, got {result:?}");
    }
}

// ── story 15 / 16: ECC ───────────────────────────────────────────────────────

/// Build a page whose stored checksum is zero (unchecked / not initialized).
///
/// This corresponds to a test fixture that never had checksums written.
#[test]
fn verify_page_checksum_unchecked_for_zero_stored() {
    let page = vec![0u8; PAGE_SIZE]; // all zeros → stored = 0
    let result = verify_page_checksum(&page, 4);
    // A zero stored checksum means "not checksummed yet" — treat as Unknown.
    assert!(
        matches!(result, ChecksumResult::Unknown),
        "all-zero page must return Unknown, got {result:?}"
    );
}

/// Build a Vista+-style page whose ECC checksum has been tampered.
///
/// Vista+ pages store an 8-byte checksum at offset 0: bytes 0–3 = XOR checksum,
/// bytes 4–7 = ECC code. This helper sets both the XOR and ECC fields for the
/// clean page, then corrupts one data byte without updating the ECC field.
fn make_tampered_ecc_page() -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    // Put some non-zero data in the page body (offset 8+ for ECC format).
    for i in (8..PAGE_SIZE).step_by(4) {
        page[i] = 0x42;
    }
    // Compute XOR over bytes 8..
    let seed: u32 = 0x89AB_CDEF;
    let mut xor_csum = seed;
    for chunk in page[8..].chunks_exact(4) {
        xor_csum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    // Compute a simple ECC over bytes 8.. (column parity scheme).
    let ecc = compute_ecc(&page[8..]);
    // Store correct XOR at offset 0, correct ECC at offset 4.
    page[0..4].copy_from_slice(&xor_csum.to_le_bytes());
    page[4..8].copy_from_slice(&ecc.to_le_bytes());
    // Now tamper one data byte — this invalidates the ECC without touching
    // the stored checksum fields.
    page[8] ^= 0xFF;
    page
}

/// Column-parity ECC: XOR of each column position across all 4-byte words.
fn compute_ecc(data: &[u8]) -> u32 {
    let mut ecc: u32 = 0;
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        ecc ^= word.rotate_left((i % 32) as u32);
    }
    ecc
}

#[test]
fn verify_page_checksum_ecc_mismatch_for_tampered_vista_page() {
    let page = make_tampered_ecc_page();
    let result = verify_page_checksum(&page, 5);
    assert!(
        matches!(result, ChecksumResult::EccMismatch),
        "tampered ECC page must return EccMismatch, got {result:?}"
    );
}
