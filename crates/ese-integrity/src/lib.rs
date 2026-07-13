//! ESE database structural anomaly detection.
//!
//! Produces raw binary-format facts ([`EseStructuralAnomaly`]) from an open
//! [`EseDatabase`]. Does NOT draw forensic conclusions — that is the job of
//! the `RapidTriage` correlation layer.

use ese_core::{EseDatabase, EseHeader};

/// The canonical 5-level severity scale, shared across every `SecurityRonin`
/// analyzer via [`forensicnomicon::report`].
pub use forensicnomicon::report::Severity;

/// A raw structural anomaly detected in an ESE database binary.
///
/// These are parsing-level observations, not forensic conclusions.
#[derive(Debug, Clone, serde::Serialize)]
pub enum EseStructuralAnomaly {
    /// Database was not cleanly shut down (state = `2`).
    DirtyDatabase { db_state: u32 },
    /// A page's `db_time` field is strictly greater than the file header's
    /// `db_time` low 32 bits — the page appears newer than the header.
    TimestampSkew {
        page_number: u32,
        header_db_time_low: u32,
        page_db_time: u32,
    },
    /// Non-zero bytes exist in the page slack region (between record data
    /// end and tag array start) — possible residual record fragments.
    SlackRegionData {
        page_number: u32,
        /// Byte offset within the page where slack begins.
        offset_in_page: u16,
        /// Number of non-zero slack bytes.
        length: u16,
    },
    /// The XOR or ECC checksum stored in the page header does not match
    /// the recomputed checksum over page bytes. Bytes changed after write.
    PageChecksumMismatch {
        page_number: u32,
        expected: u32,
        actual: u32,
    },
    /// A B-tree node's sibling-page pointer chain is broken: the declared
    /// next/previous page does not reciprocate the link.
    BTreeLinkBroken {
        page_number: u32,
        /// Page number that was supposed to link back.
        broken_sibling: u32,
    },
    /// A page is reachable via the B-tree but its `page_flags` are
    /// inconsistent with its position (e.g. leaf flag set on an internal node).
    PageFlagInconsistency {
        page_number: u32,
        flags: u16,
        context: &'static str,
    },
    /// A SRUM table identified by GUID in the catalog is referenced by
    /// a record but no corresponding B-tree root page can be found.
    OrphanedSrumTable { table_guid: String },
    /// A required SRUM table (known GUID from forensicnomicon) is absent
    /// from the catalog — the table was deleted or never populated.
    MissingSrumTable {
        table_guid: &'static str,
        table_name: &'static str,
    },
    /// The file ends before the declared page count implies. The database
    /// was truncated — either during acquisition or deliberately.
    TruncatedDatabase {
        declared_pages: u32,
        actual_pages: u32,
    },
    /// A catalog entry references a B-tree root page that falls beyond the
    /// declared page count (i.e. the page does not exist in the file).
    ///
    /// This can indicate a partially written or deliberately truncated database
    /// where the catalog was updated but the corresponding data pages were not.
    OrphanedCatalogEntry {
        /// Name of the catalog entry (table or index name).
        object_name: String,
        /// The root page number that the catalog declares.
        declared_page: u32,
        /// The highest valid page index in the file.
        last_valid_page: u32,
    },
    /// One or more `AutoIncId` values are missing from a contiguous sequence.
    ///
    /// A gap between `prev` and `next` (non-adjacent integers) indicates that
    /// records were deleted without leaving a deleted-tag marker — either via
    /// bulk deletion or external manipulation of the ESE store.
    AutoIncIdGap {
        /// The `AutoIncId` immediately before the gap.
        prev: i32,
        /// The `AutoIncId` immediately after the gap.
        next: i32,
    },
    /// A record tag has the deleted-record flag set (bit 29 of the tag word).
    ///
    /// Deleted records are not immediately zeroed; the raw bytes often persist
    /// and can contain recoverable data or evidence of prior state.
    DeletedRecordPresent {
        page_number: u32,
        /// 0-based tag index within the page's tag array.
        tag_index: usize,
    },
    /// The ESE catalog metadata (page 5 / table-of-tables) could not be read,
    /// so catalog-based checks could not run — itself a corruption/tampering
    /// signal, since a missing or malformed catalog page is the bootstrap
    /// structure every catalog check depends on.
    CatalogUnreadable {
        /// The underlying `EseError` display string (the offending value).
        detail: String,
    },
}

impl EseStructuralAnomaly {
    /// Return the forensic severity of this anomaly.
    // One variant per arm is the severity contract — keep each anomaly kind on
    // its own line for readability even when several map to the same severity.
    #[allow(clippy::match_same_arms)]
    pub fn severity(&self) -> Severity {
        match self {
            Self::DirtyDatabase { .. } => Severity::Info,
            Self::TimestampSkew { .. } => Severity::High,
            Self::SlackRegionData { .. } => Severity::Medium,
            Self::PageChecksumMismatch { .. } => Severity::High,
            Self::BTreeLinkBroken { .. } => Severity::High,
            Self::PageFlagInconsistency { .. } => Severity::Medium,
            Self::OrphanedSrumTable { .. } => Severity::Medium,
            Self::MissingSrumTable { .. } => Severity::Medium,
            Self::TruncatedDatabase { .. } => Severity::Critical,
            Self::DeletedRecordPresent { .. } => Severity::Medium,
            Self::AutoIncIdGap { .. } => Severity::Medium,
            Self::OrphanedCatalogEntry { .. } => Severity::High,
            Self::CatalogUnreadable { .. } => Severity::Critical,
        }
    }

    /// Return `true` if this anomaly's severity is at least `min`.
    pub fn at_least(&self, min: Severity) -> bool {
        self.severity() >= min
    }
}

/// Minimum number of bytes required for a parseable ESE database.
///
/// ESE stores a primary header at page 0 and a shadow copy at page 1.
/// Both must be present for reliable header reconstruction: `2 × 4096 = 8192`.
const ESE_MIN_BYTES: usize = 8192;

/// ESE header page size used when the `page_size` field cannot be parsed.
const ESE_DEFAULT_PAGE_SIZE: usize = 4096;

/// Compute the Vista+ ESE XOR page checksum.
///
/// Seeds with the logical page number (`physical_page_number - 1`), then
/// XORs every 4-byte word across the **entire** page (including bytes[0..8]).
/// For a correctly checksummed page the result equals the stored XOR value at
/// bytes[4..8]. Data beyond the last full 4-byte word is ignored.
fn xor_page_checksum_ese(page_data: &[u8], logical_pgno: u32) -> u32 {
    let mut csum = logical_pgno;
    for chunk in page_data.chunks_exact(4) {
        csum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    csum
}

/// Read-only forensic analyser for a raw ESE database byte buffer.
///
/// Operates directly on raw bytes so it can detect anomalies that would
/// prevent normal parsing (bad checksums, missing pages, truncation).
/// [`analyse`](EseIntegrity::analyse) short-circuits after any `Critical`
/// finding: a truncated file makes page-level checks meaningless.
pub struct EseIntegrity<'a> {
    data: &'a [u8],
}

impl<'a> EseIntegrity<'a> {
    /// Wrap a raw ESE database byte buffer for forensic analysis.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Run all checks and return every detected anomaly.
    ///
    /// Returns an empty `Vec` for a structurally sound database.
    /// Short-circuits after any `Critical` finding (e.g. `TruncatedDatabase`).
    pub fn analyse(&self) -> Vec<EseStructuralAnomaly> {
        let mut anomalies = self.check_layout();
        // Short-circuit: if any Critical anomaly was found, page/btree/catalog
        // checks would produce false positives on missing or unreadable pages.
        let has_critical = anomalies.iter().any(|a| a.severity() == Severity::Critical);
        if has_critical {
            return anomalies;
        }
        anomalies.extend(self.check_header());
        anomalies.extend(self.check_pages());
        anomalies.extend(self.check_btree());
        anomalies.extend(self.check_catalog());
        anomalies
    }

    /// Check for database layout problems (truncation).
    ///
    /// Returns `TruncatedDatabase` if the buffer is smaller than
    /// [`ESE_MIN_BYTES`] or shorter than the declared page count implies.
    pub fn check_layout(&self) -> Vec<EseStructuralAnomaly> {
        if self.data.len() < ESE_MIN_BYTES {
            let actual_pages =
                u32::try_from(self.data.len() / ESE_DEFAULT_PAGE_SIZE).unwrap_or(u32::MAX);
            // Try to read declared page count from header; fall back to 0.
            let declared_pages = self.try_read_declared_pages().unwrap_or(0);
            return vec![EseStructuralAnomaly::TruncatedDatabase {
                declared_pages,
                actual_pages,
            }];
        }
        // Check that the file is at least as large as the declared page count.
        let page_size = self.try_read_page_size().unwrap_or(ESE_DEFAULT_PAGE_SIZE);
        if let Some(declared) = self.try_read_declared_pages() {
            let expected_bytes = (declared as usize).saturating_mul(page_size);
            if expected_bytes > self.data.len() {
                let actual_pages = u32::try_from(self.data.len() / page_size).unwrap_or(u32::MAX);
                return vec![EseStructuralAnomaly::TruncatedDatabase {
                    declared_pages: declared,
                    actual_pages,
                }];
            }
        }
        Vec::new()
    }

    /// Check page-level integrity (XOR checksums).
    ///
    /// For each data page, verifies the stored XOR checksum at offset 0
    /// against the computed value. Pages where the stored checksum is 0 are
    /// treated as "unchecked" and skipped (common for empty/synthetic pages).
    /// Handles both legacy XOR and Vista+ ECC formats via
    /// `ese_core::verify_page_checksum()`.
    pub fn check_pages(&self) -> Vec<EseStructuralAnomaly> {
        use ese_core::{verify_page_checksum, ChecksumResult};

        let page_size = self.try_read_page_size().unwrap_or(ESE_DEFAULT_PAGE_SIZE);
        if page_size < 8 {
            return Vec::new();
        }
        let mut anomalies = Vec::new();
        // Skip page 0 (the file header page itself, which has its own checksum scheme).
        for page_number in 1u32.. {
            let start = (page_number as usize).saturating_mul(page_size);
            let end = start.saturating_add(page_size);
            if end > self.data.len() {
                break;
            }
            let page_data = &self.data[start..end];
            match verify_page_checksum(page_data, page_number) {
                ChecksumResult::Valid | ChecksumResult::Unknown => {}
                ChecksumResult::LegacyXorMismatch { stored, computed } => {
                    anomalies.push(EseStructuralAnomaly::PageChecksumMismatch {
                        page_number,
                        expected: computed,
                        actual: stored,
                    });
                }
                ChecksumResult::EccMismatch => {
                    let actual = u32::from_le_bytes([
                        page_data[0],
                        page_data[1],
                        page_data[2],
                        page_data[3],
                    ]);
                    anomalies.push(EseStructuralAnomaly::PageChecksumMismatch {
                        page_number,
                        expected: 0,
                        actual,
                    });
                }
            }
        }
        anomalies
    }

    /// Check B-tree sibling link consistency.
    ///
    /// Stub — link verification requires catalog traversal and is deferred
    /// to a future phase. Returns an empty `Vec`.
    pub fn check_btree(&self) -> Vec<EseStructuralAnomaly> {
        Vec::new()
    }

    /// Check catalog consistency (orphaned/missing SRUM tables).
    ///
    /// Stub — catalog traversal requires full B-tree walk and is deferred
    /// to a future phase. Returns an empty `Vec`.
    pub fn check_catalog(&self) -> Vec<EseStructuralAnomaly> {
        Vec::new()
    }

    /// Check header fields (dirty state reported via [`check_dirty_state`]).
    ///
    /// Stub — the caller can use [`check_dirty_state`] directly on an
    /// `EseDatabase`. Returns an empty `Vec`.
    pub fn check_header(&self) -> Vec<EseStructuralAnomaly> {
        Vec::new()
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn try_read_page_size(&self) -> Option<usize> {
        if self.data.len() < 240 {
            return None;
        }
        let raw = u32::from_le_bytes([
            self.data[236],
            self.data[237],
            self.data[238],
            self.data[239],
        ]);
        if raw == 0 {
            Some(ESE_DEFAULT_PAGE_SIZE)
        } else {
            Some(raw as usize)
        }
    }

    fn try_read_declared_pages(&self) -> Option<u32> {
        // ESE header `last_page_number` is at offset 0x1C8 (456) in the header page.
        // It stores the highest page number used, which equals page_count - 1.
        // We return page_count = last_page_number + 1.
        const LAST_PAGE_OFFSET: usize = 0x1C8;
        if self.data.len() < LAST_PAGE_OFFSET + 4 {
            return None;
        }
        let last = u32::from_le_bytes([
            self.data[LAST_PAGE_OFFSET],
            self.data[LAST_PAGE_OFFSET + 1],
            self.data[LAST_PAGE_OFFSET + 2],
            self.data[LAST_PAGE_OFFSET + 3],
        ]);
        Some(last.saturating_add(1))
    }
}

/// Verify the Vista+ ECC-32 XOR page checksum for every data page in `db`.
///
/// Pages where **both** the column-parity field (`[0..4]`) and the XOR field
/// (`[4..8]`) are zero are treated as unchecked (empty/synthetic pages) and
/// skipped silently.
///
/// For all other pages the correct algorithm is applied:
/// - `logical_pgno = page_number - 1`
/// - `csum = logical_pgno XOR (every 4-byte word in the entire page)`
/// - A mismatch against the stored XOR at bytes `[4..8]` produces
///   [`PageChecksumMismatch`].
///
/// This algorithm was confirmed correct against 326/326 non-empty pages in the
/// chainsaw SRUDB fixture (Python probe, 2026-05-20).
pub fn verify_page_checksums(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let page_count = db.page_count();
    let mut anomalies = Vec::new();
    for page_number in 1..u32::try_from(page_count).unwrap_or(u32::MAX) {
        let Ok(page) = db.read_page(page_number) else {
            continue;
        };
        if page.data.len() < 8 {
            continue;
        }
        let col_parity =
            u32::from_le_bytes([page.data[0], page.data[1], page.data[2], page.data[3]]);
        let stored_xor =
            u32::from_le_bytes([page.data[4], page.data[5], page.data[6], page.data[7]]);
        // Skip unchecked pages: both checksum fields zero means never checksummed.
        if col_parity == 0 && stored_xor == 0 {
            continue;
        }
        let logical_pgno = page_number.saturating_sub(1);
        let computed = xor_page_checksum_ese(&page.data, logical_pgno);
        if computed != stored_xor {
            anomalies.push(EseStructuralAnomaly::PageChecksumMismatch {
                page_number,
                expected: stored_xor,
                actual: computed,
            });
        }
    }
    anomalies
}

/// Run all available structural integrity checks on `db` and aggregate results.
///
/// Combines the output of:
/// - [`verify_page_checksums`] — XOR checksum mismatch detection
/// - [`find_deleted_records`] — in-place deleted-tag scanning
/// - [`detect_orphaned_catalog`] — catalog entries beyond file bounds
///
/// Note: [`detect_autoinc_gaps`] is a pure function operating on caller-
/// supplied id slices and is not included here (it has no `EseDatabase` API).
pub fn full_scan(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let mut anomalies = Vec::new();
    anomalies.extend(verify_page_checksums(db));
    anomalies.extend(find_deleted_records(db));
    anomalies.extend(detect_orphaned_catalog(db));
    anomalies
}

/// Check the catalog for table entries whose declared root page falls outside
/// the file's page range.
///
/// For each catalog entry with `object_type == 1` (table), this checks whether
/// `table_page >= page_count`. A hit means the catalog was updated but the
/// corresponding data pages were never written — either truncation or tampering.
///
/// If `db.catalog_entries()` fails (e.g. the catalog root page is missing or
/// malformed), the catalog — the bootstrap structure this detector depends on —
/// is unreadable. Rather than silently returning an empty `Vec` (which would be
/// indistinguishable from a clean catalog), this surfaces a single loud
/// [`EseStructuralAnomaly::CatalogUnreadable`] carrying the underlying error
/// string, because an unreadable catalog is itself a corruption / tampering
/// signal.
pub fn detect_orphaned_catalog(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let entries = match db.catalog_entries() {
        Ok(entries) => entries,
        Err(e) => {
            return vec![EseStructuralAnomaly::CatalogUnreadable {
                detail: e.to_string(),
            }]
        }
    };
    let last_valid = db.page_count().saturating_sub(1) as u32;
    entries
        .iter()
        .filter(|e| e.object_type == 1 && e.table_page > last_valid)
        .map(|e| EseStructuralAnomaly::OrphanedCatalogEntry {
            object_name: e.object_name.clone(),
            declared_page: e.table_page,
            last_valid_page: last_valid,
        })
        .collect()
}

/// Detect non-adjacent `AutoIncId` values in a sorted (or unsorted) id slice.
///
/// Any pair of adjacent elements where `next > prev + 1` indicates that one or
/// more records were removed without leaving an in-place deleted-tag marker.
/// The input does not need to be pre-sorted; this function sorts a copy internally.
pub fn detect_autoinc_gaps(ids: &[i32]) -> Vec<EseStructuralAnomaly> {
    if ids.len() < 2 {
        return Vec::new();
    }
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted
        .windows(2)
        .filter_map(|w| {
            let (prev, next) = (w[0], w[1]);
            if next > prev + 1 {
                Some(EseStructuralAnomaly::AutoIncIdGap { prev, next })
            } else {
                None
            }
        })
        .collect()
}

/// Scan every data page for tags that have the deleted-record flag set.
///
/// Per MS-ESEDB spec: ESE marks deleted records in-place by setting `TAG_DEFUNCT=0x2`
/// in bits 13-15 of the offset word of the 4-byte tag. In the 32-bit tag word this
/// is bit 14 (`0x4000`). The record bytes are left intact, allowing forensic recovery.
/// Each such tag is reported as [`DeletedRecordPresent`].
pub fn find_deleted_records(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    // TAG_DEFUNCT=0x2 sits at bits 13-15 of the offset word (low 16 bits of the u32).
    // bit 13 of the u32 = 0x2000, bit 14 = 0x4000; the full 3-bit flag field is 0xE000.
    // A value of 0x2 in that field means bit 14 (0x4000) is set.
    const DELETED_FLAG: u32 = 0x4000;
    let page_count = db.page_count();
    let mut anomalies = Vec::new();
    for page_number in 1..u32::try_from(page_count).unwrap_or(u32::MAX) {
        let Ok(page) = db.read_page(page_number) else {
            continue;
        };
        let Ok(hdr) = page.parse_header() else {
            continue;
        };
        let count = hdr.available_page_tag_count as usize;
        let page_size = page.data.len();
        for i in 0..count {
            let Some(tag_offset) = page_size.checked_sub((i + 1) * 4) else {
                break;
            };
            let raw = u32::from_le_bytes([
                page.data[tag_offset],
                page.data[tag_offset + 1],
                page.data[tag_offset + 2],
                page.data[tag_offset + 3],
            ]);
            if raw & DELETED_FLAG != 0 {
                anomalies.push(EseStructuralAnomaly::DeletedRecordPresent {
                    page_number,
                    tag_index: i,
                });
            }
        }
    }
    anomalies
}

/// Filter `anomalies` to those at or above `min` severity.
pub fn anomalies_at_least(
    anomalies: &[EseStructuralAnomaly],
    min: Severity,
) -> Vec<&EseStructuralAnomaly> {
    anomalies.iter().filter(|a| a.at_least(min)).collect()
}

/// Check whether the database header indicates an unclean shutdown.
///
/// Returns `Some(DirtyDatabase)` if `db_state == 2`, `None` otherwise.
pub fn check_dirty_state(header: &EseHeader) -> Option<EseStructuralAnomaly> {
    if header.db_state == ese_core::DB_STATE_DIRTY_SHUTDOWN {
        Some(EseStructuralAnomaly::DirtyDatabase {
            db_state: header.db_state,
        })
    } else {
        None
    }
}

/// Compare each page's `db_time` field (page offset `0x08`, 4 bytes) against
/// the file header's `db_time` low 32 bits.
///
/// A page whose `db_time` is **greater than** the header's indicates the page
/// was written after the header was last updated — a manipulation indicator.
pub fn detect_timestamp_skew(header: &EseHeader, db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let header_low = (header.db_time & 0xFFFF_FFFF) as u32;
    let page_count = db.page_count();
    let mut anomalies = Vec::new();
    // Start at page 1 — page 0 is the header itself, not a data page.
    for page_number in 1..u32::try_from(page_count).unwrap_or(u32::MAX) {
        let Ok(page) = db.read_page(page_number) else {
            continue;
        };
        if page.data.len() < 12 {
            continue;
        }
        // Page db_time is 4 bytes at page offset 0x08.
        let page_db_time = u32::from_le_bytes([
            page.data[0x08],
            page.data[0x09],
            page.data[0x0A],
            page.data[0x0B],
        ]);
        if page_db_time > header_low {
            anomalies.push(EseStructuralAnomaly::TimestampSkew {
                page_number,
                header_db_time_low: header_low,
                page_db_time,
            });
        }
    }
    anomalies
}

/// Scan every page for non-zero bytes in the slack region.
///
/// The slack region is the space between the last record's data end and the
/// start of the tag array at the bottom of the page. Residual bytes here
/// may contain fragments of previously deleted records.
pub fn scan_slack_regions(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let page_count = db.page_count();
    let page_size = db.header.page_size as usize;
    let mut anomalies = Vec::new();
    for page_number in 1..u32::try_from(page_count).unwrap_or(u32::MAX) {
        let Ok(page) = db.read_page(page_number) else {
            continue;
        };
        let Ok(hdr) = page.parse_header() else {
            continue;
        };
        let tag_count = hdr.available_page_tag_count as usize;
        if tag_count == 0 {
            continue;
        }
        // Tag array occupies the last tag_count * 4 bytes of the page.
        let tag_array_start = page_size.saturating_sub(tag_count * 4);
        // Find the highest data byte used by any record tag.
        let Ok(tags) = page.tags() else { continue };
        let record_data_end = tags
            .iter()
            .map(|(off, sz)| usize::from(*off) + usize::from(*sz))
            .max()
            .unwrap_or(0);
        // Slack = bytes in [record_data_end, tag_array_start)
        if record_data_end >= tag_array_start {
            continue; // no slack
        }
        let slack = &page.data[record_data_end..tag_array_start];
        let non_zero = slack.iter().any(|&b| b != 0);
        if non_zero {
            let offset_in_page = u16::try_from(record_data_end).unwrap_or(u16::MAX);
            let length = u16::try_from(slack.len()).unwrap_or(u16::MAX);
            anomalies.push(EseStructuralAnomaly::SlackRegionData {
                page_number,
                offset_in_page,
                length,
            });
        }
    }
    anomalies
}

impl EseStructuralAnomaly {
    /// Stable, scheme-prefixed machine code for this anomaly.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::DirtyDatabase { .. } => "SRUM-ESE-DIRTY-DATABASE",
            Self::TimestampSkew { .. } => "SRUM-ESE-TIMESTAMP-SKEW",
            Self::SlackRegionData { .. } => "SRUM-ESE-SLACK-REGION-DATA",
            Self::PageChecksumMismatch { .. } => "SRUM-ESE-PAGE-CHECKSUM-MISMATCH",
            Self::BTreeLinkBroken { .. } => "SRUM-ESE-BTREE-LINK-BROKEN",
            Self::PageFlagInconsistency { .. } => "SRUM-ESE-PAGE-FLAG-INCONSISTENCY",
            Self::OrphanedSrumTable { .. } => "SRUM-ESE-ORPHANED-SRUM-TABLE",
            Self::MissingSrumTable { .. } => "SRUM-ESE-MISSING-SRUM-TABLE",
            Self::TruncatedDatabase { .. } => "SRUM-ESE-TRUNCATED-DATABASE",
            Self::OrphanedCatalogEntry { .. } => "SRUM-ESE-ORPHANED-CATALOG-ENTRY",
            Self::AutoIncIdGap { .. } => "SRUM-ESE-AUTO-INC-ID-GAP",
            Self::DeletedRecordPresent { .. } => "SRUM-ESE-DELETED-RECORD-PRESENT",
            Self::CatalogUnreadable { .. } => "SRUM-ESE-CATALOG-UNREADABLE",
        }
    }
}

impl forensicnomicon::report::Observation for EseStructuralAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity())
    }
    fn code(&self) -> &'static str {
        self.code()
    }
    fn note(&self) -> String {
        self.code()
            .strip_prefix("SRUM-ESE-")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .replace('-', " ")
    }
}
