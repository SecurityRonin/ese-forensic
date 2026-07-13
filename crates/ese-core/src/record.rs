//! ESE record decoding — column definitions and value types.

use crate::EseError;

/// Result of verifying the checksum stored at the start of an ESE page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumResult {
    /// Stored checksum matches the computed value.
    Valid,
    /// Legacy XOR checksum: stored value does not match computed value.
    LegacyXorMismatch { stored: u32, computed: u32 },
    /// Vista+ ECC checksum: the stored ECC does not match the computed ECC.
    EccMismatch,
    /// Stored checksum field is zero — page was never checksummed.
    Unknown,
}

/// Verify the checksum stored at offset 0 of `page_data`.
///
/// ## Format detection heuristic
///
/// * If stored bytes 0–3 are all zero → [`ChecksumResult::Unknown`].
/// * If stored bytes 4–7 are all zero → legacy XOR format:
///   seed `0x89AB_CDEF` XOR'd with all 4-byte words from offset 4 onward.
///   Mismatch → [`ChecksumResult::LegacyXorMismatch`].
/// * If stored bytes 4–7 are non-zero → Vista+ ECC format:
///   XOR covers bytes 8+; ECC is a column-parity code over bytes 8+.
///   Mismatch → [`ChecksumResult::EccMismatch`].
///
/// `page_number` is unused in the computation but kept for diagnostic use.
pub fn verify_page_checksum(page_data: &[u8], _page_number: u32) -> ChecksumResult {
    if page_data.len() < 8 {
        return ChecksumResult::Unknown;
    }
    let stored_xor = u32::from_le_bytes([page_data[0], page_data[1], page_data[2], page_data[3]]);
    if stored_xor == 0 {
        return ChecksumResult::Unknown;
    }
    let stored_ecc = u32::from_le_bytes([page_data[4], page_data[5], page_data[6], page_data[7]]);

    if stored_ecc == 0 {
        // Legacy XOR format: covers bytes 4+.
        let computed = xor_page_checksum(&page_data[4..]);
        if computed == stored_xor {
            ChecksumResult::Valid
        } else {
            ChecksumResult::LegacyXorMismatch {
                stored: stored_xor,
                computed,
            }
        }
    } else {
        // Vista+ ECC format: XOR + column-parity ECC, both covering bytes 8+.
        if page_data.len() < 9 {
            return ChecksumResult::Unknown;
        }
        let computed_xor = xor_page_checksum(&page_data[8..]);
        let computed_ecc = column_parity_ecc(&page_data[8..]);
        if computed_xor == stored_xor && computed_ecc == stored_ecc {
            ChecksumResult::Valid
        } else {
            ChecksumResult::EccMismatch
        }
    }
}

const XOR_CHECKSUM_SEED: u32 = 0x89AB_CDEF;

fn xor_page_checksum(data: &[u8]) -> u32 {
    let mut csum = XOR_CHECKSUM_SEED;
    for chunk in data.chunks_exact(4) {
        csum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    csum
}

/// Column-parity ECC: XOR each word rotated by its position mod 32.
fn column_parity_ecc(data: &[u8]) -> u32 {
    let mut ecc: u32 = 0;
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        ecc ^= word.rotate_left((i % 32) as u32);
    }
    ecc
}

/// JET column type codes (coltyp field in `MSysObjects`).
pub mod coltyp {
    pub const BIT: u8 = 1;
    pub const UNSIGNED_BYTE: u8 = 2;
    pub const SHORT: u8 = 3;
    pub const LONG: u8 = 4;
    pub const CURRENCY: u8 = 5;
    pub const IEEE_SINGLE: u8 = 6;
    pub const IEEE_DOUBLE: u8 = 7;
    pub const DATE_TIME: u8 = 8;
    pub const BINARY: u8 = 9;
    pub const TEXT: u8 = 10;
    pub const LONG_BINARY: u8 = 11;
    pub const LONG_TEXT: u8 = 12;
    pub const GUID: u8 = 16;
    pub const UNSIGNED_SHORT: u8 = 17;
    pub const UNSIGNED_LONG: u8 = 14;
    pub const LONG_LONG: u8 = 15;
    pub const UNSIGNED_LONG_LONG: u8 = 18;
}

/// A column definition from the ESE catalog.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    /// 1-based column identifier (matches ESE catalog `column_id`).
    pub column_id: u32,
    /// Human-readable column name.
    pub name: String,
    /// JET column type code (see [`coltyp`] constants).
    pub coltyp: u8,
}

/// A decoded ESE column value.
#[derive(Debug, Clone, serde::Serialize)]
pub enum EseValue {
    Null,
    Bool(bool),
    U8(u8),
    I16(i16),
    I32(i32),
    I64(i64),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    /// OLE Automation Date: days since 1899-12-30 as a floating-point number.
    DateTime(f64),
    Binary(Vec<u8>),
    Text(String),
    Guid([u8; 16]),
}

/// Page-tag flag: the value is a defunct (deleted) entry (libesedb
/// `LIBESEDB_PAGE_TAG_FLAG_IS_DEFUNCT`).
const PAGE_TAG_FLAG_IS_DEFUNCT: u8 = 0x02;
/// Page-tag flag: the entry is prefixed with a 2-byte common-key size (Metz ESE
/// spec, page entry: "If page tag flag 0x04 is set: common page key size").
const PAGE_TAG_FLAG_HAS_COMMON_KEY_SIZE: u8 = 0x04;

/// Strip the B-tree page-entry key from a leaf/branch page value and return the
/// entry data — a data-definition record on a leaf page, or the child-page
/// pointer bytes on a branch page.
///
/// Returns `None` when the entry is marked defunct (deleted) or is malformed.
///
/// On large (>= 16384) pages of format revision >= 17 the three page-tag flag
/// bits live in the top bits of the value's second byte (`value[1] >> 5`), and
/// the entry layout is
/// `[common_key_size(2) — only if flag 0x04][local_key_size(2)][local_key][data]`.
/// libesedb clears those flag bits from `value[1]` before reading the first
/// 16-bit field, so the size read from that byte masks them off here too.
/// Reference: libesedb `libesedb_page.c` (flags in value data) and
/// `libesedb_page_tree_value.c` (key layout).
///
/// `extended` selects this layout; small/legacy pages (synthetic fixtures) store
/// the record directly with no key prefix, so the value is returned unchanged.
#[must_use]
pub fn leaf_entry_data(value: &[u8], extended: bool) -> Option<&[u8]> {
    if !extended || value.len() < 2 {
        return Some(value);
    }
    let flags = value[1] >> 5;
    if flags & PAGE_TAG_FLAG_IS_DEFUNCT != 0 {
        return None;
    }
    // The flag bits overlay the high 3 bits of value[1] (the high byte of the
    // first 16-bit field); mask them off before reading that field.
    let first_field_hi = value[1] & 0x1f;
    let (mut off, local_key_lo, local_key_hi) = if flags & PAGE_TAG_FLAG_HAS_COMMON_KEY_SIZE != 0 {
        // First field is the common key size (skipped); the local key size
        // follows at offset 2 and carries no flag overlay.
        let lo = *value.get(2)?;
        let hi = *value.get(3)?;
        (4usize, lo, hi)
    } else {
        // First field IS the local key size; its high byte is the masked value[1].
        (2usize, value[0], first_field_hi)
    };
    let local_key_size = u16::from_le_bytes([local_key_lo, local_key_hi]) as usize;
    off = off.checked_add(local_key_size)?;
    if off > value.len() {
        return None;
    }
    Some(&value[off..])
}

/// Return the fixed byte size for a fixed-length coltyp, or `None` for
/// variable-length (Binary, Text) and tagged (`LongBinary`, `LongText`) types.
pub fn fixed_col_size(coltyp: u8) -> Option<usize> {
    match coltyp {
        coltyp::BIT | coltyp::UNSIGNED_BYTE => Some(1),
        coltyp::SHORT | coltyp::UNSIGNED_SHORT => Some(2),
        coltyp::LONG | coltyp::UNSIGNED_LONG | coltyp::IEEE_SINGLE => Some(4),
        coltyp::CURRENCY
        | coltyp::IEEE_DOUBLE
        | coltyp::DATE_TIME
        | coltyp::LONG_LONG
        | coltyp::UNSIGNED_LONG_LONG => Some(8),
        coltyp::GUID => Some(16),
        _ => None, // variable or tagged
    }
}

/// Decode one fixed-length column value from `data` (exactly `fixed_col_size` bytes).
fn decode_fixed(data: &[u8], coltyp: u8) -> EseValue {
    match coltyp {
        coltyp::BIT => EseValue::Bool(data[0] != 0),
        coltyp::UNSIGNED_BYTE => EseValue::U8(data[0]),
        coltyp::SHORT => EseValue::I16(i16::from_le_bytes([data[0], data[1]])),
        coltyp::UNSIGNED_SHORT => EseValue::U16(u16::from_le_bytes([data[0], data[1]])),
        coltyp::LONG => EseValue::I32(i32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        coltyp::UNSIGNED_LONG => {
            EseValue::U32(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        coltyp::IEEE_SINGLE => {
            EseValue::F32(f32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        coltyp::CURRENCY | coltyp::LONG_LONG => EseValue::I64(i64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])),
        coltyp::UNSIGNED_LONG_LONG => EseValue::U64(u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])),
        coltyp::IEEE_DOUBLE => EseValue::F64(f64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])),
        coltyp::DATE_TIME => EseValue::DateTime(f64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])),
        coltyp::GUID => {
            let mut g = [0u8; 16];
            g.copy_from_slice(&data[..16]);
            EseValue::Guid(g)
        }
        _ => EseValue::Binary(data.to_vec()),
    }
}

/// Decode an ESE data record into named column values.
///
/// # Record format (Vista+)
///
/// ```text
/// Offset 0:  last_fixed_col_id   (u8)  — highest fixed column ID in this record
/// Offset 1:  last_var_col_idx    (u8)  — count of variable columns in this record
/// Offset 2:  var_data_offset     (u16) — offset from record start to variable data
/// Offset 4…: fixed column data (packed, column_id 1 through last_fixed_col_id)
/// var_data_offset…end-of-var: variable column data
/// (var_data_offset - 4 - fixed_size) / 2 entries before var data: end offsets
/// ```
///
/// Fixed-column data is packed contiguously in `column_id` order starting at byte 4.
/// Each column occupies exactly [`fixed_col_size`] bytes regardless of nullity
/// (null fixed columns are stored as zero bytes in their normal slot).
///
/// Variable columns follow: a 2-byte per-column end-offset array immediately
/// before the variable data (end offsets relative to `var_data_offset`).
/// High bit of an offset entry indicates a NULL variable column.
///
/// # Errors
///
/// Returns `EseError::Corrupt` if the header cannot be read or an offset is out
/// of bounds. Unknown coltypes are returned as `EseValue::Binary`.
pub fn decode_record(
    data: &[u8],
    columns: &[ColumnDef],
) -> Result<Vec<(String, EseValue)>, EseError> {
    if data.len() < 4 {
        return Ok(Vec::new());
    }

    let last_fixed_col = u32::from(data[0]);
    let num_var_cols = data[1] as usize;
    let var_data_offset = u16::from_le_bytes([data[2], data[3]]) as usize;

    let mut result = Vec::new();

    // ── fixed columns (column_id 1..=last_fixed_col) ─────────────────────────
    let mut fixed_cursor = 4usize; // fixed data starts at byte 4
    let mut fixed_col_idx = 1u32; // current column_id being read

    for col in columns {
        if fixed_col_size(col.coltyp).is_none() {
            continue; // skip variable/tagged columns in this pass
        }
        if col.column_id > last_fixed_col {
            break; // record doesn't contain this column
        }
        // Advance past any fixed columns with lower IDs that aren't in our def list.
        // (We only need to handle columns in `columns` in order; gaps between
        // column_ids in the def list mean we skip those fixed-size slots.)
        while fixed_col_idx < col.column_id {
            // Find the size of the skipped column — we don't have its def, so
            // we can't skip it without knowing its coltyp. In practice SRUM
            // column definitions are contiguous from 1, so this path is rare.
            // Conservative: bail out if gap encountered.
            fixed_col_idx += 1;
            if fixed_col_idx > last_fixed_col {
                break;
            }
        }
        if fixed_col_idx > last_fixed_col {
            break;
        }

        // Variable/tagged columns were skipped above, so this is always Some;
        // read it fallibly anyway so a future change can never turn it into a panic.
        let Some(size) = fixed_col_size(col.coltyp) else {
            continue; // cov:unreachable: fixed_col_size(col.coltyp).is_none() already `continue`d
        };
        if fixed_cursor + size > data.len() {
            break;
        }
        let val = decode_fixed(&data[fixed_cursor..fixed_cursor + size], col.coltyp);
        result.push((col.name.clone(), val));
        fixed_cursor += size;
        fixed_col_idx += 1;
    }

    // ── variable columns ─────────────────────────────────────────────────────
    if num_var_cols == 0 || var_data_offset > data.len() {
        return Ok(result);
    }
    // Variable-column end-offset array lives at var_data_offset.
    let offsets_area_start = var_data_offset;
    let offsets_area_end = offsets_area_start + num_var_cols * 2;
    if offsets_area_end > data.len() {
        return Ok(result);
    }
    // Variable data follows the offset array.
    let var_payload_start = offsets_area_end;

    let mut var_col_idx = 0usize; // 0-based index into the offset array
    let mut prev_end = 0u16; // end offset of the previous variable column

    for col in columns {
        if fixed_col_size(col.coltyp).is_some() {
            continue; // fixed column — already handled
        }
        if var_col_idx >= num_var_cols {
            break;
        }
        let off_pos = offsets_area_start + var_col_idx * 2;
        let raw_end = u16::from_le_bytes([data[off_pos], data[off_pos + 1]]);
        let is_null = raw_end & 0x8000 != 0;
        let end_offset = (raw_end & 0x7FFF) as usize;

        if !is_null {
            let start = var_payload_start + prev_end as usize;
            let end = var_payload_start + end_offset;
            if end <= data.len() && start <= end {
                let bytes = &data[start..end];
                let val = match col.coltyp {
                    coltyp::TEXT => {
                        let s = String::from_utf8_lossy(bytes).into_owned();
                        EseValue::Text(s)
                    }
                    _ => EseValue::Binary(bytes.to_vec()),
                };
                result.push((col.name.clone(), val));
            }
        }
        prev_end = raw_end & 0x7FFF;
        var_col_idx += 1;
    }

    Ok(result)
}

/// Decode a real ESE data-definition record — fixed, variable AND tagged
/// columns — using the on-disk column-id classification.
///
/// Unlike [`decode_record`] (which targets the legacy small-page fixture
/// format where byte 1 is a raw variable-column count), this reads the real
/// format where byte 1 is the highest variable data-type id. Columns are
/// classified by their catalog id: 1..=127 fixed, 128..=255 variable, >= 256
/// tagged.
///
/// `extended` selects large-page (format revision >= 17, page size >= 16384)
/// tagged decoding: a 15-bit tagged offset mask and a per-value flags byte.
///
/// # Errors
///
/// Returns `EseError::Corrupt` only if the record header is unreadable; per-
/// column decode failures degrade to that column being absent, never a panic.
pub fn decode_ese_record(
    record: &[u8],
    columns: &[ColumnDef],
    extended: bool,
) -> Result<Vec<(String, EseValue)>, EseError> {
    if record.len() < 4 {
        return Ok(Vec::new());
    }
    let last_fixed = u32::from(record[0]);
    let last_var = record[1];
    let var_data_offset = usize::from(u16::from_le_bytes([record[2], record[3]]));
    let num_var = if last_var > 127 {
        usize::from(last_var - 127)
    } else {
        0
    };

    let mut result = Vec::new();

    // ── fixed columns (id 1..=127, packed from byte 4 in id order) ───────────
    let mut cursor = 4usize;
    for col in columns.iter().filter(|c| c.column_id <= 127) {
        if col.column_id > last_fixed {
            break; // record does not contain this (or any higher) fixed column
        }
        let Some(size) = fixed_col_size(col.coltyp) else {
            break; // unsized fixed column: cannot keep the packed offset accurate
        };
        let Some(bytes) = record.get(cursor..cursor + size) else {
            break;
        };
        result.push((col.name.clone(), decode_fixed(bytes, col.coltyp)));
        cursor += size;
    }

    // ── variable columns (id 128..=255) ──────────────────────────────────────
    if num_var > 0 {
        let payload_start = var_data_offset.saturating_add(num_var * 2);
        for col in columns
            .iter()
            .filter(|c| c.column_id >= 128 && c.column_id <= 255)
        {
            let idx = (col.column_id - 128) as usize;
            if idx >= num_var {
                continue;
            }
            let prev_end = if idx == 0 {
                0usize
            } else {
                usize::from(read_le_u16(record, var_data_offset + (idx - 1) * 2) & 0x7FFF)
            };
            let raw_end = read_le_u16(record, var_data_offset + idx * 2);
            if raw_end & 0x8000 != 0 {
                continue; // NULL
            }
            let start = payload_start.saturating_add(prev_end);
            let end = payload_start.saturating_add(usize::from(raw_end & 0x7FFF));
            if let Some(bytes) = record.get(start..end) {
                result.push((
                    col.name.clone(),
                    decode_variable_or_tagged(bytes, col.coltyp),
                ));
            }
        }
    }

    // ── tagged columns (id >= 256) ───────────────────────────────────────────
    if columns.iter().any(|c| c.column_id >= 256) {
        decode_tagged_columns(
            record,
            columns,
            extended,
            var_data_offset,
            num_var,
            &mut result,
        );
    }

    Ok(result)
}

/// Read a bounds-checked little-endian `u16`, returning 0 when out of range.
fn read_le_u16(data: &[u8], off: usize) -> u16 {
    match data.get(off..off.saturating_add(2)) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}

/// Decode the tagged-data region (INDEX format) into any tagged columns
/// (id >= 256) present in `columns`.
///
/// The region begins at the end of the variable data with a tag array of
/// `{id: u16, offset: u16}` entries; the first entry's masked offset gives the
/// array size (`(offset & 0x3fff) / 4` entries). Each value spans from its
/// masked offset to the next entry's (or the record end for the last). On the
/// extended (large-page) format — or when an entry's `0x4000` bit is set — the
/// value is prefixed with a 1-byte flags byte. Reference: libesedb
/// `libesedb_data_definition.c` (INDEX tagged format).
fn decode_tagged_columns(
    record: &[u8],
    columns: &[ColumnDef],
    extended: bool,
    var_data_offset: usize,
    num_var: usize,
    result: &mut Vec<(String, EseValue)>,
) {
    // Tagged region starts right after the variable data.
    let tagged_start = if num_var > 0 {
        let last_end =
            usize::from(read_le_u16(record, var_data_offset + (num_var - 1) * 2) & 0x7FFF);
        var_data_offset
            .saturating_add(num_var * 2)
            .saturating_add(last_end)
    } else {
        var_data_offset
    };
    if tagged_start.saturating_add(4) > record.len() {
        return;
    }
    let offset_mask: u16 = if extended { 0x7FFF } else { 0x3FFF };
    let first_offset = read_le_u16(record, tagged_start + 2);
    let entry_count = usize::from(first_offset & 0x3FFF) / 4;

    // Parse the tag array: (column id, raw offset) per entry.
    let mut entries: Vec<(u16, u16)> = Vec::with_capacity(entry_count);
    for k in 0..entry_count {
        let p = tagged_start + k * 4;
        if p + 4 > record.len() {
            break;
        }
        entries.push((read_le_u16(record, p), read_le_u16(record, p + 2)));
    }

    for col in columns.iter().filter(|c| c.column_id >= 256) {
        let Some(k) = entries
            .iter()
            .position(|(id, _)| u32::from(*id) == col.column_id)
        else {
            continue; // column has no value in this record
        };
        let raw_offset = entries[k].1;
        let start = tagged_start.saturating_add(usize::from(raw_offset & offset_mask));
        let end = entries.get(k + 1).map_or(record.len(), |(_, next_off)| {
            tagged_start.saturating_add(usize::from(next_off & offset_mask))
        });
        if start > end {
            continue;
        }
        let Some(mut bytes) = record.get(start..end) else {
            continue;
        };
        // Skip the 1-byte tagged flags prefix on the extended format (or when
        // the entry's 0x4000 bit is set).
        if extended || (raw_offset & 0x4000 != 0) {
            let Some(rest) = bytes.get(1..) else {
                continue;
            };
            bytes = rest;
        }
        result.push((
            col.name.clone(),
            decode_variable_or_tagged(bytes, col.coltyp),
        ));
    }
}

/// Decode a variable/tagged column value slice by coltyp.
///
/// Text is stored as either UTF-16LE (Unicode, codepage 1200) or single-byte
/// (codepage 1252). The per-column codepage is not read from the catalog, so
/// UTF-16LE is detected from its interleaved-NUL byte pattern; the trailing NUL
/// terminator is trimmed either way.
fn decode_variable_or_tagged(bytes: &[u8], coltyp: u8) -> EseValue {
    match coltyp {
        coltyp::TEXT | coltyp::LONG_TEXT => EseValue::Text(decode_ese_text(bytes)),
        _ => EseValue::Binary(bytes.to_vec()),
    }
}

/// Decode an ESE text value, auto-detecting UTF-16LE vs single-byte text.
fn decode_ese_text(bytes: &[u8]) -> String {
    let s = if looks_like_utf16le(bytes) {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    s.trim_end_matches('\0').to_owned()
}

/// Heuristic: even-length bytes where at least half the high bytes (odd indices)
/// are NUL indicate UTF-16LE-encoded Latin-script text.
fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return false;
    }
    let high_nuls = bytes.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    high_nuls * 2 >= bytes.len() / 2
}
