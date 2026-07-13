#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Tests for ESE record decoding — Phase 1 stories 9–12.
//!
//! Each test builds a minimal hand-crafted byte slice that matches the
//! Vista+ ESE record format and asserts that [`decode_record`] extracts
//! the correct field values.

use ese_core::{coltyp, decode_record, fixed_col_size, ColumnDef, EseValue};

// ── fixed_col_size ───────────────────────────────────────────────────────────

#[test]
fn fixed_col_size_long_is_4() {
    assert_eq!(fixed_col_size(coltyp::LONG), Some(4));
}

#[test]
fn fixed_col_size_long_long_is_8() {
    assert_eq!(fixed_col_size(coltyp::LONG_LONG), Some(8));
}

#[test]
fn fixed_col_size_text_is_none() {
    assert_eq!(fixed_col_size(coltyp::TEXT), None);
}

#[test]
fn fixed_col_size_guid_is_16() {
    assert_eq!(fixed_col_size(coltyp::GUID), Some(16));
}

// ── decode_record — fixed columns ────────────────────────────────────────────

/// Build a minimal Vista+ ESE record with fixed columns only.
///
/// Header (4 bytes):
///   [0]: `last_fixed_col_id` = number of fixed columns
///   [1]: `last_var_col_idx`  = 0 (no variable columns)
///   [2..4]: `var_data_offset` = 4 + `total_fixed_bytes` (points past fixed area)
///
/// Fixed data follows immediately at byte 4.
fn make_fixed_record(columns: &[(u8, &[u8])]) -> Vec<u8> {
    let last_fixed = columns.len() as u8;
    let fixed_bytes: Vec<u8> = columns
        .iter()
        .flat_map(|(_, data)| data.iter().copied())
        .collect();
    let fixed_len = fixed_bytes.len();
    let var_data_offset = (4 + fixed_len) as u16;
    let mut rec = vec![last_fixed, 0u8];
    rec.extend_from_slice(&var_data_offset.to_le_bytes());
    rec.extend_from_slice(&fixed_bytes);
    rec
}

#[test]
fn decode_record_single_i32_column() {
    let value: i32 = 42;
    let bytes = value.to_le_bytes();
    let rec = make_fixed_record(&[(coltyp::LONG, bytes.as_slice())]);
    let defs = vec![ColumnDef {
        column_id: 1,
        name: "auto_inc_id".into(),
        coltyp: coltyp::LONG,
    }];
    let result = decode_record(&rec, &defs).expect("decode");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "auto_inc_id");
    assert!(matches!(result[0].1, EseValue::I32(42)));
}

#[test]
fn decode_record_two_fixed_columns() {
    let auto_inc: i32 = 7;
    let bytes_sent: i64 = 1_234_567;
    let mut fixed = auto_inc.to_le_bytes().to_vec();
    fixed.extend_from_slice(&bytes_sent.to_le_bytes());
    let var_offset = (4 + fixed.len()) as u16;
    let mut rec = vec![2u8, 0u8]; // 2 fixed cols, 0 var cols
    rec.extend_from_slice(&var_offset.to_le_bytes());
    rec.extend_from_slice(&fixed);

    let defs = vec![
        ColumnDef {
            column_id: 1,
            name: "auto_inc_id".into(),
            coltyp: coltyp::LONG,
        },
        ColumnDef {
            column_id: 2,
            name: "bytes_sent".into(),
            coltyp: coltyp::LONG_LONG,
        },
    ];
    let result = decode_record(&rec, &defs).expect("decode");
    assert_eq!(result.len(), 2);
    assert!(matches!(result[0].1, EseValue::I32(7)));
    assert!(matches!(result[1].1, EseValue::I64(1_234_567)));
}

#[test]
fn decode_record_three_fixed_columns() {
    let auto_inc: i32 = 1;
    let app_id: i32 = 100;
    let user_id: i32 = 200;
    let mut fixed = auto_inc.to_le_bytes().to_vec();
    fixed.extend_from_slice(&app_id.to_le_bytes());
    fixed.extend_from_slice(&user_id.to_le_bytes());
    let var_offset = (4 + fixed.len()) as u16;
    let mut rec = vec![3u8, 0u8];
    rec.extend_from_slice(&var_offset.to_le_bytes());
    rec.extend_from_slice(&fixed);

    let defs = vec![
        ColumnDef {
            column_id: 1,
            name: "auto_inc_id".into(),
            coltyp: coltyp::LONG,
        },
        ColumnDef {
            column_id: 2,
            name: "app_id".into(),
            coltyp: coltyp::LONG,
        },
        ColumnDef {
            column_id: 3,
            name: "user_id".into(),
            coltyp: coltyp::LONG,
        },
    ];
    let result = decode_record(&rec, &defs).expect("decode");
    assert_eq!(result.len(), 3);
    assert!(matches!(result[0].1, EseValue::I32(1)));
    assert!(matches!(result[1].1, EseValue::I32(100)));
    assert!(matches!(result[2].1, EseValue::I32(200)));
}

#[test]
fn decode_record_columns_beyond_last_fixed_col_are_absent() {
    // Record declares 1 fixed column; requesting 2 — second must be absent.
    let auto_inc: i32 = 5;
    let var_offset = 4 + 4u16;
    let mut rec = vec![1u8, 0u8];
    rec.extend_from_slice(&var_offset.to_le_bytes());
    rec.extend_from_slice(&auto_inc.to_le_bytes());

    let defs = vec![
        ColumnDef {
            column_id: 1,
            name: "auto_inc_id".into(),
            coltyp: coltyp::LONG,
        },
        ColumnDef {
            column_id: 2,
            name: "app_id".into(),
            coltyp: coltyp::LONG,
        },
    ];
    let result = decode_record(&rec, &defs).expect("decode");
    // Only the column that fits within last_fixed_col should appear.
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "auto_inc_id");
}

// ── decode_record — variable-length Text column ──────────────────────────────

/// Build a record with one fixed column (i32) and one variable Text column.
///
/// Variable column layout:
///   - After the 4-byte header and fixed data comes the variable offset array.
///   - Each variable column has a 2-byte end-offset (relative to `var_data_offset`).
///   - Immediately after the offset array is the variable data itself.
///
/// With 1 fixed col (4 bytes) and 1 variable col:
///   header (4) | `fixed_data` (4) | `var_end_offsets` (2) | `var_data` (N)
///   `var_data_offset` = 4 + 4 = 8   (points to start of var offset array)
///   `var_data` starts at `var_data_offset` + `num_var_cols` * 2 = 8 + 2 = 10
///   `end_offset` for col 1 = len(text)
fn make_record_with_text(fixed_val: i32, text: &str) -> Vec<u8> {
    let text_bytes = text.as_bytes();
    let var_data_offset: u16 = 8; // 4 header + 4 fixed
    let end_offset = text_bytes.len() as u16;

    let mut rec = vec![
        1u8, // last_fixed_col_id = 1
        1u8, // last_var_col_idx = 1 (one variable column)
    ];
    rec.extend_from_slice(&var_data_offset.to_le_bytes()); // bytes 2..4
    rec.extend_from_slice(&fixed_val.to_le_bytes()); // bytes 4..8 (fixed col 1)
    rec.extend_from_slice(&end_offset.to_le_bytes()); // bytes 8..10 (var end offset)
    rec.extend_from_slice(text_bytes); // bytes 10.. (var data)
    rec
}

#[test]
fn decode_record_variable_text_column() {
    let rec = make_record_with_text(99, "svchost.exe");
    let defs = vec![
        ColumnDef {
            column_id: 1,
            name: "auto_inc_id".into(),
            coltyp: coltyp::LONG,
        },
        ColumnDef {
            column_id: 129,
            name: "id_blob".into(),
            coltyp: coltyp::TEXT,
        },
    ];
    let result = decode_record(&rec, &defs).expect("decode");
    let text_col = result.iter().find(|(n, _)| n == "id_blob");
    assert!(text_col.is_some(), "variable text column must be present");
    assert!(matches!(&text_col.unwrap().1, EseValue::Text(s) if s == "svchost.exe"));
}

#[test]
fn decode_record_empty_buffer_returns_empty() {
    let defs = vec![ColumnDef {
        column_id: 1,
        name: "x".into(),
        coltyp: coltyp::LONG,
    }];
    let result = decode_record(&[], &defs).expect("decode");
    assert!(result.is_empty());
}
