//! Shared ESE test fixture builders.
//!
//! Used as a `[dev-dependency]` by ese-core, ese-integrity, and ese-carver.
//! Never compiled into release binaries.
//!
//! This crate is pure test infrastructure: it builds fixtures and panics loudly
//! on the infallible-in-practice I/O it performs (writing a temp file), so the
//! workspace `unwrap_used`/`expect_used` denies are relaxed here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

pub use ese_core::{DB_STATE_CLEAN_SHUTDOWN, DB_STATE_DIRTY_SHUTDOWN, PAGE_SIZE};
pub use ese_core::{PAGE_FLAG_LEAF, PAGE_FLAG_PARENT, PAGE_FLAG_ROOT};

use std::io::Write as _;
use tempfile::NamedTempFile;

/// Fluent builder for a single ESE data page.
///
/// Layout (Vista+, 4096 bytes):
/// - `0x00–0x27`: 40-byte page header
/// - `0x28–N`:    record data packed low→high
/// - `N+1–end`:   slack region
/// - end of page: tag array packed high→low (4 bytes per tag)
#[must_use]
pub struct PageBuilder {
    data: Vec<u8>,
    page_size: usize,
    record_offset: usize,
    tag_count: usize,
}

impl PageBuilder {
    pub fn new(page_size: usize) -> Self {
        let mut data = vec![0u8; page_size];
        // Tag 0: size=40, offset=0 — real ESE format: cb_ (size) in LOW, ib_ (offset) in HIGH.
        let tag0_raw: u32 = 40u32; // size=40 in LOW bits, offset=0 in HIGH bits
        let pos = page_size - 4;
        data[pos..pos + 4].copy_from_slice(&tag0_raw.to_le_bytes());
        // Vista+ header: tag_count at 0x22
        data[0x22..0x24].copy_from_slice(&1u16.to_le_bytes());
        Self {
            data,
            page_size,
            record_offset: 0, // relative offset (physical = HEADER_SIZE + record_offset)
            tag_count: 1,
        }
    }

    pub fn leaf(mut self) -> Self {
        // Vista+ header: page_flags at 0x24, prev/next at 0x10/0x14
        self.data[0x24..0x28].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());
        self.data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        self.data[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        self
    }

    pub fn parent(mut self) -> Self {
        let flags = PAGE_FLAG_PARENT | PAGE_FLAG_ROOT;
        // Vista+ header: page_flags at 0x24, prev/next at 0x10/0x14
        self.data[0x24..0x28].copy_from_slice(&flags.to_le_bytes());
        self.data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        self.data[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        self
    }

    /// Write a 32-bit value into the page `db_time` field at offset `0x08`.
    pub fn with_db_time(mut self, t: u32) -> Self {
        self.data[0x08..0x0C].copy_from_slice(&t.to_le_bytes());
        self
    }

    /// Append a record and its tag entry.
    pub fn add_record(mut self, record: &[u8]) -> Self {
        const HEADER_SIZE: usize = 40;
        let relative_offset = self.record_offset;
        let absolute_offset = HEADER_SIZE + relative_offset;
        self.data[absolute_offset..absolute_offset + record.len()].copy_from_slice(record);
        self.tag_count += 1;
        let offset_u32 = u32::try_from(relative_offset).expect("offset within u32");
        let len_u32 = u32::try_from(record.len()).expect("record len within u32");
        // Real ESE format: cb_ (size) in LOW 13 bits, ib_ (offset) in HIGH 13 bits.
        let tag_raw: u32 = (len_u32 & 0x1FFF) | ((offset_u32 & 0x1FFF) << 16);
        let tag_pos = self.page_size - self.tag_count * 4;
        self.data[tag_pos..tag_pos + 4].copy_from_slice(&tag_raw.to_le_bytes());
        let tag_count_u16 = u16::try_from(self.tag_count).unwrap_or(u16::MAX);
        // Vista+ header: tag_count at 0x22
        self.data[0x22..0x24].copy_from_slice(&tag_count_u16.to_le_bytes());
        self.record_offset += record.len();
        self
    }

    /// Append a 4-byte child page reference (for parent pages).
    pub fn add_child_page(self, page_num: u32) -> Self {
        self.add_record(&page_num.to_le_bytes())
    }

    /// Write bytes into the slack region (between last record and tag array).
    pub fn with_slack(mut self, bytes: &[u8]) -> Self {
        const HEADER_SIZE: usize = 40;
        let start = HEADER_SIZE + self.record_offset;
        let tag_array_start = self.page_size - self.tag_count * 4;
        debug_assert!(
            start + bytes.len() <= tag_array_start,
            "with_slack: {} bytes at offset {} would overwrite tag array (starts at {})",
            bytes.len(),
            start,
            tag_array_start
        );
        self.data[start..start + bytes.len()].copy_from_slice(bytes);
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.data
    }

    /// Build a 64-bit `db_time` at offset `0x10` (file header only).
    ///
    /// MUST be called after any `leaf()` / `parent()` call: those methods
    /// overwrite bytes `0x0C–0x14`, which overlaps this field's `0x10–0x18`.
    pub fn with_header_db_time(mut self, t: u64) -> Self {
        self.data[0x10..0x18].copy_from_slice(&t.to_le_bytes());
        self
    }

    /// Finalize as an ESE file header page (adds magic + `page_size` fields).
    pub fn into_file_header(mut self) -> Vec<u8> {
        self.data[4..8].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes());
        let page_size_u32 = u32::try_from(self.page_size).expect("page_size within u32");
        self.data[236..240].copy_from_slice(&page_size_u32.to_le_bytes());
        self.data
    }
}

/// Build a raw ESE file-header page buffer (page 0).
pub fn make_raw_header_page(db_time: u64, db_state: u32) -> Vec<u8> {
    let mut page = PageBuilder::new(PAGE_SIZE)
        .with_header_db_time(db_time)
        .into_file_header();
    // db_state lives at offset 0x28 in the file header page only
    page[0x28..0x2C].copy_from_slice(&db_state.to_le_bytes());
    page
}

/// Assembles a header page + optional data pages into a `NamedTempFile`.
#[must_use]
pub struct EseFileBuilder {
    db_time: u64,
    db_state: u32,
    extra_pages: Vec<Vec<u8>>,
}

impl Default for EseFileBuilder {
    fn default() -> Self {
        Self {
            db_time: 0,
            db_state: DB_STATE_CLEAN_SHUTDOWN,
            extra_pages: vec![],
        }
    }
}

impl EseFileBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_db_time(mut self, t: u64) -> Self {
        self.db_time = t;
        self
    }
    pub fn with_db_state(mut self, s: u32) -> Self {
        self.db_state = s;
        self
    }

    pub fn add_page(mut self, page: Vec<u8>) -> Self {
        self.extra_pages.push(page);
        self
    }

    pub fn write(self) -> NamedTempFile {
        let header = make_raw_header_page(self.db_time, self.db_state);
        let mut tmp = NamedTempFile::new().expect("tempfile");
        tmp.write_all(&header).expect("write header");
        for page in &self.extra_pages {
            tmp.write_all(page).expect("write page");
        }
        tmp
    }
}
