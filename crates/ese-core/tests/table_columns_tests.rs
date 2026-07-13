#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Tests for `EseDatabase::table_columns` — Phase 1 stories 7–8.

mod fixtures;
use ese_core::{coltyp, CatalogEntry, EseDatabase};

fn make_db_with_id_map_columns() -> (EseDatabase, tempfile::NamedTempFile) {
    let entries = vec![
        CatalogEntry {
            object_type: 1,
            object_id: 5,
            parent_object_id: 0,
            table_page: 10,
            object_name: "SruDbIdMapTable".to_owned(),
        },
        CatalogEntry {
            object_type: 2,
            object_id: 1,
            parent_object_id: 5,
            table_page: u32::from(coltyp::LONG),
            object_name: "AutoIncId".to_owned(),
        },
        CatalogEntry {
            object_type: 2,
            object_id: 2,
            parent_object_id: 5,
            table_page: u32::from(coltyp::LONG),
            object_name: "IdType".to_owned(),
        },
        CatalogEntry {
            object_type: 2,
            object_id: 3,
            parent_object_id: 5,
            table_page: u32::from(coltyp::TEXT),
            object_name: "IdBlob".to_owned(),
        },
    ];
    let tmp = fixtures::make_ese_with_catalog(&entries);
    let db = EseDatabase::open(tmp.path()).expect("open db");
    (db, tmp)
}

#[test]
fn table_columns_returns_three_defs_for_id_map_table() {
    let (db, _tmp) = make_db_with_id_map_columns();
    let cols = db.table_columns("SruDbIdMapTable").expect("table_columns");
    assert_eq!(cols.len(), 3);
}

#[test]
fn table_columns_first_column_id_and_name() {
    let (db, _tmp) = make_db_with_id_map_columns();
    let cols = db.table_columns("SruDbIdMapTable").expect("table_columns");
    assert_eq!(cols[0].column_id, 1);
    assert_eq!(cols[0].name, "AutoIncId");
    assert_eq!(cols[0].coltyp, coltyp::LONG);
}

#[test]
fn table_columns_third_column_is_text() {
    let (db, _tmp) = make_db_with_id_map_columns();
    let cols = db.table_columns("SruDbIdMapTable").expect("table_columns");
    assert_eq!(cols[2].column_id, 3);
    assert_eq!(cols[2].name, "IdBlob");
    assert_eq!(cols[2].coltyp, coltyp::TEXT);
}

#[test]
fn table_columns_unknown_table_returns_not_found() {
    let (db, _tmp) = make_db_with_id_map_columns();
    let result = db.table_columns("NoSuchTable");
    assert!(matches!(
        result,
        Err(ese_core::EseError::TableNotFound { .. })
    ));
}
