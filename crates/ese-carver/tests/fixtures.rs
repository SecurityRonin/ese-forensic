#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Thin fixture wrappers over [`ese_test_fixtures`] for ese-carver tests.
#![allow(dead_code)]

use ese_core::DB_STATE_CLEAN_SHUTDOWN;
use ese_test_fixtures::{make_raw_header_page, PageBuilder};

pub use ese_test_fixtures::PAGE_SIZE;

/// Build a flat byte slice: header page + one complete-record page per record.
pub fn make_flat_complete(records: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = make_raw_header_page(0, DB_STATE_CLEAN_SHUTDOWN);
    for record in records {
        let page = PageBuilder::new(PAGE_SIZE)
            .leaf()
            .add_record(record)
            .build();
        buf.extend_from_slice(&page);
    }
    buf
}

/// Build a flat byte slice: header + `page_a` (prefix) + `page_b` (suffix).
pub fn make_flat_split(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let page_a = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(prefix)
        .build();
    let page_b = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(suffix)
        .build();
    let mut buf = make_raw_header_page(0, DB_STATE_CLEAN_SHUTDOWN);
    buf.extend_from_slice(&page_a);
    buf.extend_from_slice(&page_b);
    buf
}
