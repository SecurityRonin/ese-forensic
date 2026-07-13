#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Per-table column isolation — catalog columns must be keyed by their owning
//! table, not globally deduplicated by column name.
//!
//! Real ESE databases (e.g. WebCacheV01.dat) contain many tables that share
//! column names (`Url`, `AccessedTime`, ...). Deduplicating catalog columns by
//! name globally collapses them so all but one table lose those columns. Each
//! table must retain its own full column set.

mod fixtures;
use ese_core::{coltyp, CatalogEntry, EseDatabase};

fn two_tables_sharing_a_column_name() -> (EseDatabase, tempfile::NamedTempFile) {
    let entries = vec![
        CatalogEntry {
            object_type: 1,
            object_id: 5,
            parent_object_id: 0,
            table_page: 10,
            object_name: "TableA".to_owned(),
        },
        // Column "Url" in TableA — same name AND same column id as TableB's.
        CatalogEntry {
            object_type: 2,
            object_id: 256,
            parent_object_id: 5,
            table_page: u32::from(coltyp::LONG_TEXT),
            object_name: "Url".to_owned(),
        },
        CatalogEntry {
            object_type: 1,
            object_id: 6,
            parent_object_id: 0,
            table_page: 11,
            object_name: "TableB".to_owned(),
        },
        CatalogEntry {
            object_type: 2,
            object_id: 256,
            parent_object_id: 6,
            table_page: u32::from(coltyp::LONG_TEXT),
            object_name: "Url".to_owned(),
        },
    ];
    let tmp = fixtures::make_ese_with_catalog(&entries);
    let db = EseDatabase::open(tmp.path()).expect("open");
    (db, tmp)
}

#[test]
fn each_table_keeps_its_own_shared_name_column() {
    let (db, _tmp) = two_tables_sharing_a_column_name();
    let a = db.table_columns("TableA").expect("TableA columns");
    let b = db.table_columns("TableB").expect("TableB columns");
    assert_eq!(a.len(), 1, "TableA must keep its own Url column");
    assert_eq!(b.len(), 1, "TableB must keep its own Url column");
    assert_eq!(a[0].name, "Url");
    assert_eq!(b[0].name, "Url");
}
