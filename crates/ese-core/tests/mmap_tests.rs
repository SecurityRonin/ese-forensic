#![allow(clippy::unwrap_used, clippy::expect_used)]

//! TDD RED: tests for `EseDatabase::raw_page_slice`.
//!
//! These tests verify the zero-copy mmap slice API. They compile-fail until
//! `raw_page_slice` is added in the GREEN commit.
mod fixtures;

use ese_core::EseDatabase;

#[test]
fn raw_page_slice_len_equals_page_size() {
    let header = fixtures::make_ese_header_page();
    let data_page = fixtures::make_leaf_page_with_records(0, &[vec![0xABu8; 8]]);
    let tmp = fixtures::write_ese_file(&[header, data_page]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let slice = db.raw_page_slice(1).expect("page 1 in range");
    assert_eq!(slice.len(), db.header.page_size as usize);
}

#[test]
fn raw_page_slice_returns_correct_bytes() {
    // Page 1 first byte is 0xAB — verify zero-copy slice matches read_page data.
    let header = fixtures::make_ese_header_page();
    let data_page = fixtures::make_leaf_page_with_records(0, &[vec![0xABu8; 8]]);
    let tmp = fixtures::write_ese_file(&[header, data_page]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let slice = db.raw_page_slice(1).expect("page 1 in range");
    let page = db.read_page(1).expect("read_page page 1");
    assert_eq!(
        slice,
        page.data.as_slice(),
        "raw_page_slice must match read_page data"
    );
}

#[test]
fn raw_page_slice_consistent_with_read_page() {
    // Two data pages — verify both slices are independent and correct.
    let header = fixtures::make_ese_header_page();
    let page1 = fixtures::make_leaf_page_with_records(0, &[vec![0x11u8; 4]]);
    let page2 = fixtures::make_leaf_page_with_records(0, &[vec![0x22u8; 4]]);
    let tmp = fixtures::write_ese_file(&[header, page1, page2]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let s1 = db.raw_page_slice(1).expect("page 1");
    let s2 = db.raw_page_slice(2).expect("page 2");
    assert_ne!(s1, s2, "different pages must yield different slices");
    assert_eq!(s1, db.read_page(1).expect("rp1").data.as_slice());
    assert_eq!(s2, db.read_page(2).expect("rp2").data.as_slice());
}

#[test]
fn raw_page_slice_out_of_bounds_returns_err() {
    // Only header page exists (page 0). Reading page 5 must be Err.
    let header = fixtures::make_ese_header_page();
    let tmp = fixtures::write_ese_file(&[header]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let result = db.raw_page_slice(5);
    assert!(result.is_err(), "out-of-bounds slice must return Err");
}
