#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Tests for `PageBuilder` and `EseFileBuilder`.
use ese_test_fixtures::{EseFileBuilder, PageBuilder, PAGE_SIZE};

#[test]
fn page_builder_produces_correct_page_size() {
    let page = PageBuilder::new(PAGE_SIZE).leaf().build();
    assert_eq!(page.len(), PAGE_SIZE);
}

#[test]
fn page_builder_leaf_sets_leaf_flag() {
    let page = PageBuilder::new(PAGE_SIZE).leaf().build();
    // Vista+ header: page_flags at 0x24
    let flags = u32::from_le_bytes(page[0x24..0x28].try_into().unwrap());
    assert!(
        flags & ese_core::PAGE_FLAG_LEAF != 0,
        "leaf flag must be set"
    );
}

#[test]
fn page_builder_add_record_increments_tag_count() {
    let page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&[0xAAu8; 16])
        .build();
    // Vista+ header: tag_count at 0x22
    let tag_count = u16::from_le_bytes(page[0x22..0x24].try_into().unwrap());
    assert_eq!(tag_count, 2, "tag0 (header) + tag1 (data record)");
}

#[test]
fn page_builder_record_bytes_readable_from_tag() {
    let record = vec![0xBBu8; 8];
    let page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&record)
        .build();
    // tag1 is at PAGE_SIZE - 2*4 = PAGE_SIZE - 8
    let tag_pos = PAGE_SIZE - 8;
    let raw = u32::from_le_bytes(page[tag_pos..tag_pos + 4].try_into().unwrap());
    // Real ESE format: cb_ (size) in LOW 13 bits, ib_ (offset) in HIGH 13 bits.
    let size = (raw & 0x1FFF) as usize;
    let relative_offset = ((raw >> 16) & 0x1FFF) as usize;
    let absolute_offset = 40 + relative_offset; // tag offsets are relative to header end
    assert_eq!(size, 8);
    assert_eq!(&page[absolute_offset..absolute_offset + size], &record[..]);
}

#[test]
fn page_builder_with_db_time_writes_at_offset_0x08() {
    let page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .with_db_time(0xDEAD_BEEF)
        .build();
    let val = u32::from_le_bytes(page[0x08..0x0C].try_into().unwrap());
    assert_eq!(val, 0xDEAD_BEEF);
}

#[test]
fn page_builder_with_slack_writes_nonzero_bytes_in_slack_region() {
    let slack = vec![0xFFu8; 4];
    let page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .with_slack(&slack)
        .build();
    assert!(page[40..44].iter().any(|&b| b != 0));
}

#[test]
fn ese_file_builder_write_produces_readable_file() {
    let tmp = EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .write();
    assert!(tmp.path().exists());
    let meta = std::fs::metadata(tmp.path()).unwrap();
    assert_eq!(
        usize::try_from(meta.len()).expect("len fits"),
        PAGE_SIZE,
        "header-only file = one page"
    );
}

#[test]
fn ese_file_builder_add_page_grows_file() {
    let extra = PageBuilder::new(PAGE_SIZE).leaf().build();
    let tmp = EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(extra)
        .write();
    let meta = std::fs::metadata(tmp.path()).unwrap();
    assert_eq!(
        usize::try_from(meta.len()).expect("len fits"),
        PAGE_SIZE * 2
    );
}

#[test]
fn ese_file_builder_output_opens_with_ese_core() {
    let tmp = EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .write();
    ese_core::EseDatabase::open(tmp.path()).expect("must open with ese-core");
}
