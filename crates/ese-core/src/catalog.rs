//! ESE catalog reader.
//!
//! The catalog lives at page 4 and maps table names to their root B-tree
//! pages. This implementation uses a synthetic record format suitable for
//! test fixtures.
//!
//! Synthetic catalog record layout (all little-endian):
//!
//! - bytes `0..2`: `object_type` (u16): 1 = table, 2 = column, etc.
//! - bytes `2..6`: `object_id` (u32)
//! - bytes `6..10`: `parent_object_id` (u32)
//! - bytes `10..14`: `table_page` (u32) — root page of this table's B-tree
//! - bytes `14..16`: `name_len` (u16)
//! - bytes `16..`: name bytes (UTF-8)

use crate::EseError;

/// Read a little-endian `u32` from `data` at `off`, bounds-checked.
///
/// Returns 0 when the 4-byte window falls outside `data` — never panics. ESE
/// records come from untrusted, attacker-controllable images, so every offset
/// read must degrade gracefully rather than index out of bounds.
fn le_u32_at(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

/// One entry from the ESE catalog.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    /// Object type: 1 = table, 2 = column, etc.
    pub object_type: u16,
    /// Object ID.
    pub object_id: u32,
    /// Parent object ID.
    pub parent_object_id: u32,
    /// Root page number for this table's B-tree.
    pub table_page: u32,
    /// Object name (table name, column name, etc.).
    pub object_name: String,
}

impl CatalogEntry {
    /// Minimum record size.
    pub const MIN_SIZE: usize = 16;

    /// Parse one catalog record from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::Corrupt`] if the slice is too short or
    /// the name bytes are not valid UTF-8.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EseError> {
        if data.len() < Self::MIN_SIZE {
            return Err(EseError::Corrupt {
                page: 0,
                detail: format!(
                    "catalog record too short: {} < {}",
                    data.len(),
                    Self::MIN_SIZE
                ),
            });
        }
        let object_type = u16::from_le_bytes([data[0], data[1]]);
        let object_id = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let parent_object_id = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
        let table_page = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
        let name_len = u16::from_le_bytes([data[14], data[15]]) as usize;
        if data.len() < Self::MIN_SIZE + name_len {
            return Err(EseError::Corrupt {
                page: 0,
                detail: format!(
                    "catalog record name truncated: need {}, got {}",
                    Self::MIN_SIZE + name_len,
                    data.len()
                ),
            });
        }
        let name_bytes = &data[16..16 + name_len];
        let object_name = std::str::from_utf8(name_bytes)
            .map_err(|e| EseError::Corrupt {
                page: 0,
                detail: format!("catalog name not UTF-8: {e}"),
            })?
            .to_owned();
        Ok(Self {
            object_type,
            object_id,
            parent_object_id,
            table_page,
            object_name,
        })
    }

    /// Serialize this entry to bytes (for building test fixtures).
    pub fn to_bytes(&self) -> Vec<u8> {
        let name_bytes = self.object_name.as_bytes();
        let mut out = Vec::with_capacity(Self::MIN_SIZE + name_bytes.len());
        out.extend_from_slice(&self.object_type.to_le_bytes());
        out.extend_from_slice(&self.object_id.to_le_bytes());
        out.extend_from_slice(&self.parent_object_id.to_le_bytes());
        out.extend_from_slice(&self.table_page.to_le_bytes());
        out.extend_from_slice(&(u16::try_from(name_bytes.len()).unwrap_or(u16::MAX)).to_le_bytes());
        out.extend_from_slice(name_bytes);
        out
    }

    /// Scan the raw data area of an ESE catalog leaf page for all TABLE entries.
    ///
    /// Unlike [`parse_real_catalog_record`], which scans a single tag's bytes
    /// and returns the first match, this function scans the entire page data
    /// area (from the end of the 40-byte header to the start of the tag array)
    /// and returns every distinct entry found.
    ///
    /// Real ESE catalog leaf pages use a cumulative key-prefix-compression
    /// format where the first logical records can reside in the page data area
    /// before the offset of the first tag.  Scanning individual tags therefore
    /// misses those early records.  This function avoids that problem by
    /// scanning the full data span directly.
    ///
    /// Entries are deduplicated by `object_name` — if the same name appears
    /// more than once (because the cumulative format causes successive tags to
    /// re-include earlier data), only the first occurrence is kept.
    pub fn scan_catalog_page_data(data_area: &[u8]) -> Vec<Self> {
        const MIN_I: usize = 20; // need ≥20 bytes before \xff for obj_id + pgnoFDP
        const MAX_NAME: usize = 64;
        let len = data_area.len();
        let mut entries: Vec<Self> = Vec::new();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut i = MIN_I;
        while i + 4 <= len {
            if data_area[i] != 0xff || data_area[i + 1] != 0x00 {
                i += 1;
                continue;
            }
            let name_len = u16::from_le_bytes([data_area[i + 2], data_area[i + 3]]) as usize;
            if name_len == 0 || name_len > MAX_NAME || i + 4 + name_len > len {
                i += 1;
                continue;
            }
            let name_bytes = &data_area[i + 4..i + 4 + name_len];
            if !name_bytes.is_ascii() {
                i += 1;
                continue;
            }
            let Ok(name) = std::str::from_utf8(name_bytes) else {
                i += 1;
                continue;
            };
            if name.is_empty() || seen.contains(name) {
                i += 1;
                continue;
            }
            // i >= 20 here, so i-16 and i-20 are both in-bounds. Read each u32
            // through a bounds-checked slice so a future change to the loop guard
            // can never turn these into a panic on attacker-controlled bytes.
            let pgnofdf_raw = le_u32_at(data_area, i - 16);
            let object_id = le_u32_at(data_area, i - 20);
            seen.insert(name);
            entries.push(Self {
                object_type: 1,
                object_id,
                parent_object_id: 1,
                // 0-based ESE page → physical page; saturate so a hostile
                // u32::MAX pgnoFDP cannot overflow (an out-of-range page is
                // rejected later by read_page).
                table_page: pgnofdf_raw.saturating_add(1),
                object_name: name.to_owned(),
            });
            i += 4 + name_len;
        }
        entries
    }

    /// Try to parse a real ESE catalog TABLE entry from a leaf-page tag byte slice.
    ///
    /// Real ESE `MSysObjects` records use a tagged-column encoding where the `Name`
    /// column (column 128) is preceded by a two-byte marker `[0xFF, 0x00]` followed
    /// by a two-byte LE length and the ASCII name bytes.  The `pgnoFDP` (root B-tree
    /// page of the table) lives 16 bytes before the `0xFF` marker, and the object ID
    /// lives 20 bytes before it — both as u32 LE.
    ///
    /// `pgnoFDP` is stored as an ESE 0-based data-page number; this function adds 1
    /// to convert it to the physical page number expected by [`EseDatabase::read_page`].
    ///
    /// Returns `None` if the slice contains no recognisable TABLE entry.
    pub fn parse_real_catalog_record(data: &[u8]) -> Option<Self> {
        const MIN_BEFORE: usize = 20; // need ≥20 bytes before 0xFF for object_id + pgnoFDP + gap
        let len = data.len();
        let mut i = MIN_BEFORE;
        while i + 4 <= len {
            if data[i] != 0xff || data[i + 1] != 0x00 {
                i += 1;
                continue;
            }
            let name_len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
            if name_len == 0 || i + 4 + name_len > len {
                i += 1;
                continue;
            }
            let name_bytes = &data[i + 4..i + 4 + name_len];
            if !name_bytes.is_ascii() {
                i += 1;
                continue;
            }
            let Ok(name) = std::str::from_utf8(name_bytes) else {
                i += 1;
                continue;
            };
            if name.is_empty() {
                i += 1;
                continue;
            }
            let pgnofdf_raw = u32::from_le_bytes(data[i - 16..i - 12].try_into().ok()?);
            let object_id = u32::from_le_bytes(data[i - 20..i - 16].try_into().ok()?);
            let table_page = pgnofdf_raw.saturating_add(1); // ESE 0-based → physical page
            return Some(Self {
                object_type: 1,
                object_id,
                parent_object_id: 1,
                table_page,
                object_name: name.to_owned(),
            });
        }
        None
    }

    /// Decode a real ESE `MSysObjects` (catalog) data-definition record into a
    /// [`CatalogEntry`].
    ///
    /// Returns `None` for records that are not a table (`Type` 1) or column
    /// (`Type` 2), or that are too short to hold the fixed columns used here.
    ///
    /// `MSysObjects` has a fixed, well-known schema (the catalog is
    /// self-describing; libesedb bootstraps it). The fixed columns used are:
    ///
    /// | id | name              | type  | fixed offset |
    /// |----|-------------------|-------|--------------|
    /// | 1  | `ObjidTable`      | Int32 | 4            |
    /// | 2  | `Type`            | Int16 | 8            |
    /// | 3  | `Id`              | Int32 | 10           |
    /// | 4  | `ColtypOrPgnoFDP` | Int32 | 14           |
    ///
    /// `Name` is the first variable-size column (id 128). For a **table** row
    /// `ColtypOrPgnoFDP` is the root B-tree page (`pgnoFDP`, ESE 0-based →
    /// physical `+1`); for a **column** row it is the JET column type. Columns
    /// are linked to their table by `ObjidTable` (the parent table's FDP), so a
    /// table sets both `object_id` and `parent_object_id` to `ObjidTable`.
    #[must_use]
    pub fn decode_catalog_record(record: &[u8]) -> Option<Self> {
        // Data-definition header: last_fixed(1), last_var(1), var_data_offset(2).
        let last_fixed = *record.first()?;
        let last_var = *record.get(1)?;
        let var_data_offset = u16::from_le_bytes([*record.get(2)?, *record.get(3)?]) as usize;
        // Need at least fixed columns 1..=4 (packed at offsets 4, 8, 10, 14).
        if last_fixed < 4 {
            return None;
        }
        let objid_table = read_le_u32(record, 4)?;
        let obj_type = i16::from_le_bytes([*record.get(8)?, *record.get(9)?]);
        let id = read_le_u32(record, 10)?;
        let coltyp_or_pgno = read_le_u32(record, 14)?;
        let name = decode_first_variable(record, last_var, var_data_offset)?;

        match obj_type {
            // Table: root page = pgnoFDP + 1 (ESE 0-based → physical).
            1 => Some(Self {
                object_type: 1,
                object_id: objid_table,
                parent_object_id: objid_table,
                table_page: coltyp_or_pgno.saturating_add(1),
                object_name: name,
            }),
            // Column: table_page carries the JET coltyp; parent is ObjidTable.
            2 => Some(Self {
                object_type: 2,
                object_id: id,
                parent_object_id: objid_table,
                table_page: coltyp_or_pgno,
                object_name: name,
            }),
            _ => None,
        }
    }
}

/// Read a little-endian `u32` at `off`, or `None` if it falls outside `data`.
fn read_le_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Decode the first variable-size column (e.g. `MSysObjects.Name`) of a
/// data-definition record.
///
/// `last_var` is the highest variable data-type id present; the number of
/// variable columns is `last_var - 127`. The variable end-offset array (2 bytes
/// per column, high bit = NULL) starts at `var_data_offset`; the value data
/// follows the array. Returns `None` when there are no variable columns, the
/// first is NULL, or any offset falls out of bounds.
fn decode_first_variable(record: &[u8], last_var: u8, var_data_offset: usize) -> Option<String> {
    if last_var <= 127 {
        return None;
    }
    let num_var = usize::from(last_var - 127);
    let payload_start = var_data_offset.checked_add(num_var.checked_mul(2)?)?;
    if payload_start > record.len() {
        return None;
    }
    let raw_end = u16::from_le_bytes([
        *record.get(var_data_offset)?,
        *record.get(var_data_offset.checked_add(1)?)?,
    ]);
    if raw_end & 0x8000 != 0 {
        return None; // NULL
    }
    let end = payload_start.checked_add(usize::from(raw_end & 0x7fff))?;
    let bytes = record.get(payload_start..end)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_entry_roundtrip() {
        let entry = CatalogEntry {
            object_type: 1,
            object_id: 10,
            parent_object_id: 1,
            table_page: 42,
            object_name: "SruDbNetworkTable".to_owned(),
        };
        let bytes = entry.to_bytes();
        let parsed = CatalogEntry::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.object_name, "SruDbNetworkTable");
        assert_eq!(parsed.table_page, 42);
        assert_eq!(parsed.object_type, 1);
    }

    #[test]
    fn catalog_entry_too_short_returns_err() {
        let result = CatalogEntry::from_bytes(&[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_real_catalog_record_extracts_name_and_page() {
        // Build a minimal real-format catalog record:
        // 20 bytes before 0xFF: [object_id at -20..-16][pgnoFDP at -16..-12][12 bytes padding]
        // then: [0xFF][0x00][name_len u16 LE][name bytes]
        let object_id: u32 = 42;
        let pgnofdf_raw: u32 = 31; // ESE page 31 → physical page 32
        let name = b"SruDbIdMapTable";
        let name_len = name.len() as u16;

        let mut data = vec![0u8; 20 + 4 + name.len()];
        // object_id at offset 0 (= i-20)
        data[0..4].copy_from_slice(&object_id.to_le_bytes());
        // pgnoFDP at offset 4 (= i-16)
        data[4..8].copy_from_slice(&pgnofdf_raw.to_le_bytes());
        // 12 bytes of zero padding (offsets 8..20)
        // 0xFF 0x00 marker at offset 20 (= i)
        data[20] = 0xff;
        data[21] = 0x00;
        data[22..24].copy_from_slice(&name_len.to_le_bytes());
        data[24..24 + name.len()].copy_from_slice(name);

        let entry = CatalogEntry::parse_real_catalog_record(&data).expect("must find TABLE entry");
        assert_eq!(entry.object_name, "SruDbIdMapTable");
        assert_eq!(entry.table_page, 32); // pgnoFDP + 1
        assert_eq!(entry.object_id, 42);
        assert_eq!(entry.object_type, 1);
    }

    #[test]
    fn parse_real_catalog_record_max_pgnofdp_does_not_overflow() {
        // pgnoFDP = u32::MAX from hostile bytes must not panic on the 0-based →
        // physical (+1) conversion; it saturates instead.
        let name = b"MaxTable";
        let name_len = name.len() as u16;
        let mut data = vec![0u8; 20 + 4 + name.len()];
        data[4..8].copy_from_slice(&u32::MAX.to_le_bytes()); // pgnoFDP at i-16
        data[20] = 0xff;
        data[21] = 0x00;
        data[22..24].copy_from_slice(&name_len.to_le_bytes());
        data[24..24 + name.len()].copy_from_slice(name);

        let entry = CatalogEntry::parse_real_catalog_record(&data).expect("TABLE entry");
        assert_eq!(entry.table_page, u32::MAX);
    }

    #[test]
    fn scan_catalog_page_data_max_pgnofdp_does_not_overflow() {
        // Same overflow guard for the page-scan variant.
        let name = b"MaxTable";
        let name_len = name.len() as u16;
        let mut data = vec![0u8; 20 + 4 + name.len()];
        data[4..8].copy_from_slice(&u32::MAX.to_le_bytes()); // pgnoFDP at i-16
        data[20] = 0xff;
        data[21] = 0x00;
        data[22..24].copy_from_slice(&name_len.to_le_bytes());
        data[24..24 + name.len()].copy_from_slice(name);

        let entries = CatalogEntry::scan_catalog_page_data(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].table_page, u32::MAX);
    }

    #[test]
    fn parse_real_catalog_record_returns_none_for_synthetic_format() {
        // Synthetic format starts with object_type u16 = [0x01, 0x00],
        // which does not contain the 0xFF marker, so must return None.
        let entry = CatalogEntry {
            object_type: 1,
            object_id: 2,
            parent_object_id: 1,
            table_page: 100,
            object_name: "OrphanedTable".to_owned(),
        };
        let bytes = entry.to_bytes();
        assert!(
            CatalogEntry::parse_real_catalog_record(&bytes).is_none(),
            "synthetic format must not match real catalog scanner"
        );
    }
}
