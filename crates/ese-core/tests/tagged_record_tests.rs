#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Tagged-column (data-type id >= 256) record decoding.
//!
//! WebCache's `Url`/`Filename` are tagged columns stored in the record's tagged
//! data region after the fixed and variable data. The region begins with a tag
//! array of `{id: u16, offset: u16}` entries; the first entry's masked offset
//! gives the array size. On large (extended) pages each tagged value is
//! prefixed with a 1-byte flags byte and the offset field uses a 15-bit mask.
//! Reference: libesedb `libesedb_data_definition.c` (INDEX tagged format) and
//! the Metz ESE spec, tagged data types.

use ese_core::{coltyp, decode_ese_record, ColumnDef, EseValue};

/// Build a real-format record: one fixed Int32 column (id 1) plus two tagged
/// columns (ids 256, 257), using the extended (large-page) tagged layout with a
/// 1-byte flags prefix per value.
fn make_tagged_record(fixed: i32, tag256: &[u8], tag257: &[u8]) -> Vec<u8> {
    let mut rec = Vec::new();
    // Data-definition header: last_fixed=1, last_var=127 (no variable columns),
    // var_data_offset points past the 4-byte fixed data.
    rec.push(1); // last_fixed
    rec.push(127); // last_var (127 => zero variable columns)
    let var_data_offset: u16 = 8; // 4 header + 4 fixed
    rec.extend_from_slice(&var_data_offset.to_le_bytes());
    rec.extend_from_slice(&fixed.to_le_bytes()); // fixed col 1 (bytes 4..8)

    // Tagged region starts here (== var_data_offset, no variable data).
    // Tag array: 2 entries × 4 bytes = 8 bytes; value data follows.
    // Each value carries a 1-byte flags prefix (extended format).
    let v256 = {
        let mut v = vec![0u8];
        v.extend_from_slice(tag256);
        v
    };
    let v257 = {
        let mut v = vec![0u8];
        v.extend_from_slice(tag257);
        v
    };
    let off0: u16 = 8; // first value at region-relative offset 8 (past the array)
    let off1: u16 = off0 + v256.len() as u16;
    rec.extend_from_slice(&256u16.to_le_bytes());
    rec.extend_from_slice(&off0.to_le_bytes());
    rec.extend_from_slice(&257u16.to_le_bytes());
    rec.extend_from_slice(&off1.to_le_bytes());
    rec.extend_from_slice(&v256);
    rec.extend_from_slice(&v257);
    rec
}

#[test]
fn decode_ese_record_extracts_tagged_columns() {
    // tag 256 = UTF-16LE "hi"; tag 257 = binary bytes.
    let url_utf16: Vec<u8> = "hi".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let blob = [0xDE, 0xAD, 0xBEu8];
    let rec = make_tagged_record(42, &url_utf16, &blob);
    let cols = vec![
        ColumnDef {
            column_id: 1,
            name: "EntryId".into(),
            coltyp: coltyp::LONG,
        },
        ColumnDef {
            column_id: 256,
            name: "Url".into(),
            coltyp: coltyp::LONG_TEXT,
        },
        ColumnDef {
            column_id: 257,
            name: "Blob".into(),
            coltyp: coltyp::LONG_BINARY,
        },
    ];
    let vals = decode_ese_record(&rec, &cols, true).expect("decode");

    let fixed = vals.iter().find(|(n, _)| n == "EntryId");
    assert!(
        matches!(fixed, Some((_, EseValue::I32(42)))),
        "fixed column must still decode"
    );
    let url = vals.iter().find(|(n, _)| n == "Url").map(|(_, v)| v);
    assert!(
        matches!(url, Some(EseValue::Text(s)) if s == "hi"),
        "tagged UTF-16LE Url must decode to 'hi', got {url:?}"
    );
    let b = vals.iter().find(|(n, _)| n == "Blob").map(|(_, v)| v);
    assert!(
        matches!(b, Some(EseValue::Binary(bytes)) if bytes == &blob),
        "tagged binary column must decode, got {b:?}"
    );
}
