//! ESE database header (first 4096 bytes of the file).

use crate::error::EseError;

/// Database state constants (offset 0x28 in file header).
pub const DB_STATE_JUST_CREATED: u32 = 1;
/// Database closed uncleanly; a transaction log replay is required.
pub const DB_STATE_DIRTY_SHUTDOWN: u32 = 2;
/// Database closed cleanly.
pub const DB_STATE_CLEAN_SHUTDOWN: u32 = 3;

/// Parsed ESE database file header.
#[derive(Debug, Clone)]
pub struct EseHeader {
    /// ESE magic: `0x89ABCDEF` (little-endian at offset 4).
    pub signature: u32,
    /// Database format version.
    pub format_version: u32,
    /// Page size in bytes (typically 4096 or 8192).
    pub page_size: u32,
    /// Database time field (offset `0x10`, 8 bytes LE).
    ///
    /// Stored as a `JET_LOGTIME`-derived u64. The low 32 bits are compared
    /// against per-page `db_time` values to detect timestamp skew.
    pub db_time: u64,
    /// Database state (offset `0x28`).
    ///
    /// `2` = dirty shutdown (log replay needed), `3` = clean shutdown.
    pub db_state: u32,
}

impl EseHeader {
    /// Size of the ESE header block (first full page).
    pub const SIZE: usize = 4096;

    /// Parse an ESE header from the first 4096 bytes of a database file.
    ///
    /// ESE header layout (all little-endian):
    /// - Offset 0x00 (4 bytes): checksum
    /// - Offset 0x04 (4 bytes): signature (0x89ABCDEF)
    /// - Offset 0x08 (4 bytes): format version
    /// - Offset 0x0C (4 bytes): format revision
    /// - Offset 0xEC (4 bytes): page size (0 means 4096)
    pub fn from_bytes(data: &[u8]) -> Result<Self, EseError> {
        // Only the four power-of-two sizes that ESE actually uses are valid.
        // Any other value indicates a corrupt or crafted header.
        const VALID_PAGE_SIZES: [u32; 4] = [4096, 8192, 16384, 32768];
        if data.len() < Self::SIZE {
            return Err(EseError::Corrupt {
                page: 0,
                detail: format!(
                    "file too short: need {} bytes, got {}",
                    Self::SIZE,
                    data.len()
                ),
            });
        }
        let sig = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if sig != 0x89AB_CDEF {
            return Err(EseError::InvalidMagic {
                page: 0,
                found: sig,
            });
        }
        let format_version = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        // db_time at offset 0x10 (8 bytes LE)
        let db_time = u64::from_le_bytes([
            data[0x10], data[0x11], data[0x12], data[0x13], data[0x14], data[0x15], data[0x16],
            data[0x17],
        ]);
        // db_state at offset 0x28 (4 bytes LE)
        let db_state = u32::from_le_bytes([data[0x28], data[0x29], data[0x2A], data[0x2B]]);
        // Page size is at offset 0xEC = 236.
        // 0 is a special sentinel meaning "use the default 4096".
        let raw_page_size = u32::from_le_bytes([data[236], data[237], data[238], data[239]]);
        let page_size = if raw_page_size == 0 {
            4096
        } else {
            raw_page_size
        };
        if !VALID_PAGE_SIZES.contains(&page_size) {
            return Err(EseError::Corrupt {
                page: 0,
                detail: format!(
                    "invalid page_size {page_size}: must be one of 4096, 8192, 16384, 32768"
                ),
            });
        }
        Ok(EseHeader {
            signature: sig,
            format_version,
            page_size,
            db_time,
            db_state,
        })
    }
}
