#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for ese-catalog story.
//!
//! Tests [`EseDatabase::catalog_entries`] and [`EseDatabase::find_table_page`].

mod fixtures;
use ese_core::{CatalogEntry, EseDatabase};

#[test]
fn catalog_entries_returns_at_least_one_entry() {
    let entries = vec![
        CatalogEntry {
            object_type: 1,
            object_id: 2,
            parent_object_id: 1,
            table_page: 5,
            object_name: "SruDbNetworkTable".to_owned(),
        },
        CatalogEntry {
            object_type: 1,
            object_id: 3,
            parent_object_id: 1,
            table_page: 6,
            object_name: "SruDbIdMapTable".to_owned(),
        },
    ];
    let tmp = fixtures::make_ese_with_catalog(&entries);
    let db = EseDatabase::open(tmp.path()).expect("open db");
    let result = db.catalog_entries().expect("catalog_entries");
    assert!(!result.is_empty(), "expected at least one catalog entry");
}

#[test]
fn catalog_entries_have_object_name_and_table_page() {
    let entries = vec![CatalogEntry {
        object_type: 1,
        object_id: 2,
        parent_object_id: 1,
        table_page: 42,
        object_name: "SruDbNetworkTable".to_owned(),
    }];
    let tmp = fixtures::make_ese_with_catalog(&entries);
    let db = EseDatabase::open(tmp.path()).expect("open db");
    let result = db.catalog_entries().expect("catalog_entries");
    let entry = result
        .iter()
        .find(|e| e.object_name == "SruDbNetworkTable")
        .expect("SruDbNetworkTable entry");
    assert_eq!(entry.table_page, 42);
}

#[test]
fn find_table_page_returns_correct_page() {
    let entries = vec![CatalogEntry {
        object_type: 1,
        object_id: 2,
        parent_object_id: 1,
        table_page: 99,
        object_name: "SruDbNetworkTable".to_owned(),
    }];
    let tmp = fixtures::make_ese_with_catalog(&entries);
    let db = EseDatabase::open(tmp.path()).expect("open db");
    let page_num = db
        .find_table_page("SruDbNetworkTable")
        .expect("find_table_page");
    assert_eq!(page_num, 99);
}

#[test]
fn find_table_page_unknown_returns_err() {
    let entries = vec![CatalogEntry {
        object_type: 1,
        object_id: 2,
        parent_object_id: 1,
        table_page: 5,
        object_name: "SruDbNetworkTable".to_owned(),
    }];
    let tmp = fixtures::make_ese_with_catalog(&entries);
    let db = EseDatabase::open(tmp.path()).expect("open db");
    let result = db.find_table_page("NonExistentTable");
    assert!(result.is_err(), "unknown table must return Err");
}
