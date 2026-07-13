#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for `TableCursor` — ese-cursor story.
mod fixtures;

use ese_core::EseDatabase;

#[test]
fn table_records_from_root_yields_record_bytes() {
    let record = vec![0xABu8; 16];
    let header = fixtures::make_ese_header_page();
    let leaf = fixtures::make_leaf_page_with_records(0, std::slice::from_ref(&record));
    // page 0 = header, page 1 = leaf
    let tmp = fixtures::write_ese_file(&[header, leaf]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let mut cursor = db.table_records_from_root(1).expect("cursor");
    let first = cursor.next().expect("at least one record");
    let (page_num, tag_idx, bytes) = first.expect("no error");
    assert_eq!(page_num, 1u32);
    assert_eq!(
        tag_idx, 1usize,
        "data starts at tag 1 (tag 0 is page header)"
    );
    assert_eq!(bytes, record);
}

#[test]
fn table_records_from_root_empty_leaf_yields_none() {
    let header = fixtures::make_ese_header_page();
    let leaf = fixtures::make_leaf_page_with_records(0, &[]);
    let tmp = fixtures::write_ese_file(&[header, leaf]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let mut cursor = db.table_records_from_root(1).expect("cursor");
    assert!(cursor.next().is_none(), "empty leaf must yield None");
}

#[test]
fn table_records_returns_table_not_found_for_unknown_table() {
    use ese_core::EseError;
    let entry = ese_core::CatalogEntry {
        object_type: 1,
        object_id: 2,
        parent_object_id: 1,
        table_page: 5,
        object_name: "KnownTable".to_owned(),
    };
    let tmp = fixtures::make_ese_with_catalog(&[entry]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let err = db
        .table_records("NonExistent")
        .expect_err("unknown table must error");
    assert!(
        matches!(err, EseError::TableNotFound { .. }),
        "got: {err:?}"
    );
}

#[test]
fn table_records_from_root_two_records_both_yielded() {
    let r1 = vec![0x11u8; 8];
    let r2 = vec![0x22u8; 8];
    let header = fixtures::make_ese_header_page();
    let leaf = fixtures::make_leaf_page_with_records(0, &[r1.clone(), r2.clone()]);
    let tmp = fixtures::write_ese_file(&[header, leaf]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let cursor = db.table_records_from_root(1).expect("cursor");
    let results: Vec<_> = cursor.collect();
    assert_eq!(results.len(), 2, "both records must be yielded");
    let (_, t1, b1) = results[0].as_ref().expect("record 1 ok");
    let (_, t2, b2) = results[1].as_ref().expect("record 2 ok");
    assert_eq!(*t1, 1usize);
    assert_eq!(*t2, 2usize);
    assert_eq!(*b1, r1);
    assert_eq!(*b2, r2);
}
