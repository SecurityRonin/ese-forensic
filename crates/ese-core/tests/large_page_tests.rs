#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Large-page (16 KiB / 32 KiB) tag-decoding regression tests.
//!
//! For ESE format revision 17 and later, pages of 16384 and 32768 bytes use the
//! full 15-bit page-tag offset/size fields (mask `0x7fff`); the tag flag bits
//! that live in the top 3 bits on small (<= 8 KiB) pages are instead stored in
//! the page value data. Masking a large-page tag with the small-page `0x1fff`
//! truncates any offset/size above 8191, corrupting every record and B-tree
//! child pointer on the page.
//!
//! Reference: libesedb `libesedb_page.c` (page tag offset/size masking:
//! `0x7fff` when `format_revision >= 17 && page_size >= 16384`, else `0x1fff`)
//! and the Metz "ESE Database File (EDB) format" spec, page tag section.

use ese_core::EsePage;

const HEADER_SIZE: usize = 40;
/// Value-data base on a large page: 40-byte standard header + 40-byte extended
/// page header (three ECC checksums + page number + reserved).
const LARGE_PAGE_VALUE_BASE: usize = 80;

/// Build a large ESE page with one record whose relative tag offset exceeds the
/// 13-bit (`0x1fff` = 8191) small-page limit.
fn make_large_page_with_high_offset(page_size: usize, rel_offset: u16, record: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; page_size];
    // Vista+ header: tag_count at 0x22, PAGE_FLAG_LEAF at 0x24.
    d[0x22..0x24].copy_from_slice(&2u16.to_le_bytes());
    d[0x24..0x28].copy_from_slice(&2u32.to_le_bytes()); // PAGE_FLAG_LEAF
    d[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    d[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // Record at absolute value-data base (past the extended header) + rel_offset.
    let abs = LARGE_PAGE_VALUE_BASE + rel_offset as usize;
    d[abs..abs + record.len()].copy_from_slice(record);

    // Tag 0: size=40, offset=0 (page header). ESE: size in LOW 15 bits, offset HIGH.
    d[page_size - 4..page_size].copy_from_slice(&40u32.to_le_bytes());
    // Tag 1: size=record.len, offset=rel_offset. 15-bit fields.
    let sz = record.len() as u32;
    let tag1: u32 = (sz & 0x7FFF) | ((u32::from(rel_offset) & 0x7FFF) << 16);
    d[page_size - 8..page_size - 4].copy_from_slice(&tag1.to_le_bytes());
    d
}

#[test]
fn tags_16k_page_offset_above_8191_not_truncated() {
    // rel_offset 9000 > 8191: under the small-page 0x1fff mask this becomes
    // 9000 & 0x1fff = 808, pointing at the wrong bytes. The 0x7fff mask keeps 9000.
    let sentinel = [0xDE, 0xAD, 0xBE, 0xEFu8];
    let data = make_large_page_with_high_offset(16384, 9000, &sentinel);
    let page = EsePage {
        page_number: 1,
        data,
    };
    let tags = page.tags().expect("tags");
    assert_eq!(
        tags[1],
        (9000u16, 4u16),
        "16 KiB page tag offset must use the 15-bit 0x7fff mask, not 0x1fff"
    );
    assert_eq!(
        page.record_data(1).expect("record_data(1)"),
        &sentinel,
        "record at relative offset 9000 must be read from the correct position"
    );
}

#[test]
fn tags_32k_page_offset_above_16383_not_truncated() {
    // rel_offset 20000: needs the full 15 bits on a 32 KiB page.
    let sentinel = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06u8];
    let data = make_large_page_with_high_offset(32768, 20000, &sentinel);
    let page = EsePage {
        page_number: 1,
        data,
    };
    let tags = page.tags().expect("tags");
    assert_eq!(tags[1], (20000u16, 6u16));
    assert_eq!(page.record_data(1).expect("record_data(1)"), &sentinel);
}

#[test]
fn tags_4k_page_still_uses_small_mask() {
    // A 4 KiB page keeps the legacy 0x1fff mask + top-3-bit flags: an offset of
    // 100 with flag bits set in the top 3 bits must mask down to 100.
    let mut d = vec![0u8; 4096];
    d[0x22..0x24].copy_from_slice(&2u16.to_le_bytes());
    d[0x24..0x28].copy_from_slice(&2u32.to_le_bytes());
    d[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    d[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let sentinel = [0xAAu8; 4];
    d[HEADER_SIZE + 100..HEADER_SIZE + 104].copy_from_slice(&sentinel);
    d[4096 - 4..4096].copy_from_slice(&40u32.to_le_bytes());
    // size=4, offset=100, with flag bits 0b111 in the top 3 bits of the offset field.
    let tag1: u32 = 4u32 | (((100u32 & 0x1FFF) | (0b111 << 13)) << 16);
    d[4096 - 8..4096 - 4].copy_from_slice(&tag1.to_le_bytes());
    let page = EsePage {
        page_number: 1,
        data: d,
    };
    let tags = page.tags().expect("tags");
    assert_eq!(
        tags[1],
        (100u16, 4u16),
        "4 KiB page must strip the top-3 flag bits with the 0x1fff mask"
    );
}
