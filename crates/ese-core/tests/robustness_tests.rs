#![allow(clippy::unwrap_used, clippy::expect_used)]

//! ese-core input robustness tests — Phase 18-C.
//!
//! Tests crafted malformed inputs that should be rejected at parse time.
//! Each test documents the exact flaw being guarded and the expected behaviour.

use ese_core::{EseHeader, EsePage};

/// Build a minimal valid ESE header buffer with the given raw `page_size` value.
fn header_buf_with_page_size(raw_page_size: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    // ESE magic at offset 4
    buf[4..8].copy_from_slice(&0x89AB_CDEF_u32.to_le_bytes());
    // page_size at offset 0xEC = 236
    buf[236..240].copy_from_slice(&raw_page_size.to_le_bytes());
    buf
}

// ── page_size validation ─────────────────────────────────────────────────────

#[test]
fn page_size_1_is_rejected() {
    // page_size = 1 is not in {4096, 8192, 16384, 32768}; must return Err.
    let buf = header_buf_with_page_size(1);
    let result = EseHeader::from_bytes(&buf);
    assert!(
        result.is_err(),
        "page_size=1 must be rejected; EseDatabase using it as a slice multiplier would misbehave"
    );
}

#[test]
fn page_size_33000_is_rejected() {
    // page_size = 33000 > 32768; must return Err.
    let buf = header_buf_with_page_size(33000);
    let result = EseHeader::from_bytes(&buf);
    assert!(
        result.is_err(),
        "page_size=33000 must be rejected (> 32768)"
    );
}

#[test]
fn page_size_5000_is_rejected() {
    // 5000 is not a power-of-two ESE page size; must return Err.
    let buf = header_buf_with_page_size(5000);
    let result = EseHeader::from_bytes(&buf);
    assert!(
        result.is_err(),
        "page_size=5000 must be rejected (not in valid set)"
    );
}

#[test]
fn page_size_4096_is_accepted() {
    let buf = header_buf_with_page_size(4096);
    let result = EseHeader::from_bytes(&buf);
    assert!(result.is_ok(), "page_size=4096 must be accepted");
    assert_eq!(result.unwrap().page_size, 4096);
}

#[test]
fn page_size_8192_is_accepted() {
    let buf = header_buf_with_page_size(8192);
    let result = EseHeader::from_bytes(&buf);
    assert!(result.is_ok(), "page_size=8192 must be accepted");
    assert_eq!(result.unwrap().page_size, 8192);
}

#[test]
fn page_size_16384_is_accepted() {
    let buf = header_buf_with_page_size(16384);
    let result = EseHeader::from_bytes(&buf);
    assert!(result.is_ok(), "page_size=16384 must be accepted");
    assert_eq!(result.unwrap().page_size, 16384);
}

#[test]
fn page_size_32768_is_accepted() {
    let buf = header_buf_with_page_size(32768);
    let result = EseHeader::from_bytes(&buf);
    assert!(result.is_ok(), "page_size=32768 must be accepted");
    assert_eq!(result.unwrap().page_size, 32768);
}

#[test]
fn page_size_zero_defaults_to_4096() {
    // page_size = 0 has a special meaning: "use the default 4096".
    let buf = header_buf_with_page_size(0);
    let result = EseHeader::from_bytes(&buf);
    assert!(result.is_ok(), "page_size=0 must be accepted (means 4096)");
    assert_eq!(result.unwrap().page_size, 4096);
}

// ── tag offset bounds check in EsePage::tags() ──────────────────────────────

/// Build a page where a tag declares `offset + size > page_size`, which is
/// out-of-bounds. Currently `tags()` returns the bad (offset, size) pair
/// without error; after the fix it must return `Err`.
fn make_page_with_out_of_bounds_tag(page_size: usize) -> EsePage {
    let mut data = vec![0u8; page_size];
    // 2 tags (tag 0 + tag 1); tag 0 = page header (offset=0, size=40)
    let tag_count: u16 = 2;
    // Vista+ header: tag_count at 0x22, page_flags at 0x24
    data[0x22..0x24].copy_from_slice(&tag_count.to_le_bytes());
    data[0x24..0x28].copy_from_slice(&ese_core::PAGE_FLAG_LEAF.to_le_bytes());

    // Real ESE format: cb_ (size) in LOW bits, ib_ (offset) in HIGH bits.
    // Tag 0: size=40, offset=0 → 40u32
    let tag0: u32 = 40u32;
    let pos0 = page_size - 4;
    data[pos0..pos0 + 4].copy_from_slice(&tag0.to_le_bytes());

    // Tag 1: size=4000, offset=100 → 100+4000=4140 > page_size(4096) — invalid
    let offset: u32 = 100;
    let size: u32 = 4000; // HEADER_SIZE(40) + offset(100) + size(4000) = 4140 > 4096
    let tag1: u32 = (size & 0x1FFF) | ((offset & 0x1FFF) << 16);
    let pos1 = page_size - 8;
    data[pos1..pos1 + 4].copy_from_slice(&tag1.to_le_bytes());

    EsePage {
        page_number: 1,
        data,
    }
}

#[test]
fn tags_with_out_of_bounds_offset_returns_err() {
    let page = make_page_with_out_of_bounds_tag(4096);
    // tags() must return Err when any tag's offset+size exceeds page data length.
    let result = page.tags();
    assert!(
        result.is_err(),
        "tags() must return Err when tag offset+size ({}) > page_size ({})",
        100 + 4000,
        4096
    );
}

// ── tag size field uses 13-bit mask (0x1FFF), not 15-bit (0x7FFF) ────────────

/// Build a page with one tag whose cb_ (size, LOW bits) has bits 13-14 set,
/// simulating real SRUDB.dat tags where the size word carries extra flag bits.
/// `raw=0x4010_000A` from chainsaw: LOW=0x000A (cb_/size=10), HIGH=0x4010 (ib_/offset=16).
/// This function tests the cb_ masking: `true_size` | 0x4000 in the LOW bits.
fn make_page_with_high_size_bits(page_size: usize, true_size: usize) -> EsePage {
    let mut data = vec![0u8; page_size];
    let tag_count: u16 = 1;
    data[0x22..0x24].copy_from_slice(&tag_count.to_le_bytes());
    data[0x24..0x28].copy_from_slice(&ese_core::PAGE_FLAG_LEAF.to_le_bytes());

    // Real ESE: cb_ (size) in LOW bits, ib_ (offset) in HIGH bits.
    // Tag 0: size=true_size with bit 14 set (0x4000), offset=0.
    // With 0x7FFF mask: size = true_size | 0x4000 (too large)
    // With 0x1FFF mask: size = true_size (correct)
    let size_word = u32::try_from(true_size | 0x4000).expect("size within u32");
    let tag0: u32 = size_word; // size_word in LOW bits, offset=0 in HIGH bits
    let pos = page_size - 4;
    data[pos..pos + 4].copy_from_slice(&tag0.to_le_bytes());

    EsePage {
        page_number: 1,
        data,
    }
}

#[test]
fn tags_strips_high_bits_from_size_word_returns_13bit_size() {
    // Real SRUDB.dat cb_ (size, LOW bits) sometimes has bits 13+ set (format flags).
    // tags() must mask them to 0x1FFF to return the true record size.
    // Raw 0x4010_000A: cb_=0x000A (size=10), ib_=0x4010 (offset=16 after 0x1FFF mask).
    let true_size: usize = 16;
    let page = make_page_with_high_size_bits(4096, true_size);
    let tags = page.tags().expect("tags must succeed — no out-of-bounds");
    assert_eq!(
        tags[0].1 as usize, true_size,
        "size must be the 13-bit cb_ value (0x1FFF mask), not the full 15-bit word"
    );
}

#[test]
fn tags_strips_high_bits_from_offset_word_returns_13bit_offset() {
    // ib_ (offset, HIGH bits) can have flag bits 13-15 set (e.g. DEFUNCT bit 13).
    // tags() must mask to 0x1FFF to return the true record offset.
    let mut data = vec![0u8; 4096];
    let tag_count: u16 = 1;
    data[0x22..0x24].copy_from_slice(&tag_count.to_le_bytes());
    data[0x24..0x28].copy_from_slice(&ese_core::PAGE_FLAG_LEAF.to_le_bytes());

    // Real ESE: cb_ (size) in LOW bits, ib_ (offset) in HIGH bits.
    // offset=10 with DEFUNCT flag (bit 13 of ib_ word = 0x2000):
    // ib_word = 10 | 0x2000 = 0x200A → stored in HIGH 16 bits; cb_=4 in LOW 16 bits.
    let tag0: u32 = 4u32 | ((10u32 | 0x2000u32) << 16);
    let pos = 4096 - 4;
    data[pos..pos + 4].copy_from_slice(&tag0.to_le_bytes());

    let page = EsePage {
        page_number: 1,
        data,
    };
    let tags = page.tags().expect("tags must succeed");
    assert_eq!(
        tags[0].0 as usize, 10,
        "offset must be the 13-bit ib_ value (0x1FFF mask), stripping flag bits"
    );
}
