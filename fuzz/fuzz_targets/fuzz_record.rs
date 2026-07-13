#![no_main]
//! Fuzz record decoding and page checksum verification. The first byte seeds a
//! small synthetic column schema; the remainder is decoded as a record body and
//! also run through the checksum verifier. Must never panic on malformed data.
use ese_core::{
    coltyp, decode_ese_record, decode_record, leaf_entry_data, verify_page_checksum, ColumnDef,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Checksum verification over the raw buffer.
    let _ = verify_page_checksum(data, 1);

    // Build a small mixed fixed/variable/tagged column schema from the first
    // byte so decode_record has something to walk, then decode the rest.
    let seed = data.first().copied().unwrap_or(0);
    let columns = vec![
        ColumnDef {
            column_id: 1,
            name: "a".to_string(),
            coltyp: coltyp::UNSIGNED_LONG,
        },
        ColumnDef {
            column_id: 2,
            name: "b".to_string(),
            coltyp: coltyp::LONG_LONG,
        },
        ColumnDef {
            column_id: 3,
            name: "c".to_string(),
            coltyp: if seed & 1 == 0 {
                coltyp::TEXT
            } else {
                coltyp::LONG_TEXT
            },
        },
    ];
    let body = data.get(1..).unwrap_or(&[]);
    let _ = decode_record(body, &columns);
    let _ = decode_record(data, &[]);

    // Real record decoder with fixed + variable + tagged columns. Add tagged
    // (id >= 256) and variable (128..=255) columns so the tagged-data and
    // variable-offset paths are exercised on arbitrary bytes.
    let real_columns = vec![
        ColumnDef {
            column_id: 1,
            name: "f".to_string(),
            coltyp: coltyp::LONG_LONG,
        },
        ColumnDef {
            column_id: 128,
            name: "v".to_string(),
            coltyp: coltyp::TEXT,
        },
        ColumnDef {
            column_id: 256,
            name: "t".to_string(),
            coltyp: if seed & 2 == 0 {
                coltyp::LONG_TEXT
            } else {
                coltyp::LONG_BINARY
            },
        },
        ColumnDef {
            column_id: 257,
            name: "u".to_string(),
            coltyp: coltyp::LONG_TEXT,
        },
    ];
    let extended = seed & 4 == 0;
    let _ = decode_ese_record(body, &real_columns, extended);
    let _ = decode_ese_record(data, &real_columns, !extended);

    // B-tree leaf/branch entry key stripping over arbitrary bytes.
    let _ = leaf_entry_data(data, true);
    let _ = leaf_entry_data(data, false);
});
