//! ESE database page types.

use crate::EseError;

/// Default ESE page size in bytes (Vista+).
pub const PAGE_SIZE: usize = 4096;

/// Page flag: root page.
pub const PAGE_FLAG_ROOT: u32 = 0x0001;
/// Page flag: leaf page.
pub const PAGE_FLAG_LEAF: u32 = 0x0002;
/// Page flag: parent (internal B-tree node).
pub const PAGE_FLAG_PARENT: u32 = 0x0004;
/// Page flag: empty page.
pub const PAGE_FLAG_EMPTY: u32 = 0x0008;
/// Page flag: space tree page (`OWN_EXT` / `AVAIL_EXT`).
pub const PAGE_FLAG_SPACE_TREE: u32 = 0x0020;
/// Page flag: long-value page (stores overflow data for LongBinary/LongText columns).
pub const PAGE_FLAG_LONG_VALUE: u32 = 0x0400;

/// Parsed ESE page header fields (Vista+ "new" 40-byte format).
#[derive(Debug, Clone)]
pub struct EsePageHeader {
    /// Previous page number; `None` when `0xFFFF_FFFF`.
    pub prev_page: Option<u32>,
    /// Next page number; `None` when `0xFFFF_FFFF`.
    pub next_page: Option<u32>,
    /// Father data page object ID.
    pub fdp_object_id: u32,
    /// Available data size.
    pub available_data_size: u16,
    /// Available uncommitted data.
    pub available_uncommitted: u16,
    /// Available data offset.
    pub available_data_offset: u16,
    /// Number of page tags (includes tag 0).
    pub available_page_tag_count: u16,
    /// Page flags.
    pub page_flags: u32,
}

/// A single ESE database page.
#[derive(Debug, Clone)]
pub struct EsePage {
    /// Page number (1-based).
    pub page_number: u32,
    /// Raw page data. Parse flags via [`EsePage::parse_header`].
    pub data: Vec<u8>,
}

impl EsePage {
    /// Minimum size of the Vista+ page header.
    pub const HEADER_SIZE: usize = 40;

    /// Parse the Vista+ 40-byte page header from `self.data`.
    ///
    /// Layout (all little-endian):
    /// - 0x00 (4): XOR checksum
    /// - 0x04 (4): ECC checksum (Vista+ addition)
    /// - 0x08 (8): database time (`JET_DBTIME`)
    /// - 0x10 (4): previous page number
    /// - 0x14 (4): next page number
    /// - 0x18 (4): FDP object ID
    /// - 0x1C (2): available data size
    /// - 0x1E (2): available uncommitted data
    /// - 0x20 (2): available data offset
    /// - 0x22 (2): available page tag count
    /// - 0x24 (4): page flags
    ///
    /// # Errors
    ///
    /// Returns [`EseError::Corrupt`] if `self.data` is shorter than 40 bytes.
    pub fn parse_header(&self) -> Result<EsePageHeader, EseError> {
        let d = &self.data;
        if d.len() < Self::HEADER_SIZE {
            return Err(EseError::Corrupt {
                page: self.page_number,
                detail: format!("page header too short: {} < {}", d.len(), Self::HEADER_SIZE),
            });
        }

        let prev_raw = u32::from_le_bytes([d[0x10], d[0x11], d[0x12], d[0x13]]);
        let next_raw = u32::from_le_bytes([d[0x14], d[0x15], d[0x16], d[0x17]]);
        let fdp_object_id = u32::from_le_bytes([d[0x18], d[0x19], d[0x1A], d[0x1B]]);
        let available_data_size = u16::from_le_bytes([d[0x1C], d[0x1D]]);
        let available_uncommitted = u16::from_le_bytes([d[0x1E], d[0x1F]]);
        let available_data_offset = u16::from_le_bytes([d[0x20], d[0x21]]);
        let available_page_tag_count = u16::from_le_bytes([d[0x22], d[0x23]]);
        let page_flags = u32::from_le_bytes([d[0x24], d[0x25], d[0x26], d[0x27]]);

        Ok(EsePageHeader {
            prev_page: if prev_raw == 0xFFFF_FFFF {
                None
            } else {
                Some(prev_raw)
            },
            next_page: if next_raw == 0xFFFF_FFFF {
                None
            } else {
                Some(next_raw)
            },
            fdp_object_id,
            available_data_size,
            available_uncommitted,
            available_data_offset,
            available_page_tag_count,
            page_flags,
        })
    }

    /// Return the tag entries from the end of the page.
    ///
    /// Tags are stored at the END of the page, growing downward.
    /// Each tag is 4 bytes: bits 0-14 = value offset, bit 15 = flag,
    /// bits 16-30 = value size, bit 31 = flag.
    ///
    /// Returns `Vec<(offset, size)>` for each tag.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::TagArrayOverflow`] if the page is too short to hold the
    /// declared tag count.
    pub fn tags(&self) -> Result<Vec<(u16, u16)>, EseError> {
        let hdr = self.parse_header()?;
        let count = hdr.available_page_tag_count as usize;
        let page_size = self.data.len();
        if page_size < count * 4 {
            return Err(EseError::TagArrayOverflow {
                page: self.page_number,
            });
        }
        let mut tags = Vec::with_capacity(count);
        for i in 0..count {
            let tag_offset = page_size - (i + 1) * 4;
            let raw = u32::from_le_bytes([
                self.data[tag_offset],
                self.data[tag_offset + 1],
                self.data[tag_offset + 2],
                self.data[tag_offset + 3],
            ]);
            // ESE TAG struct layout (MS-ESEDB §2.2.7.1):
            //   cb_ (SIZE)   = low  16 bits (bits  0-12 are value, bits 13-15 are flags)
            //   ib_ (OFFSET) = high 16 bits (bits 16-28 are value, bits 29-31 are flags)
            // Mask 0x1FFF strips the flag bits from each 13-bit field.
            let value_size = (raw & 0x1FFF) as u16; // cb_ = SIZE
            let value_offset = ((raw >> 16) & 0x1FFF) as u16; // ib_ = OFFSET
                                                              // Guard: absolute position = HEADER_SIZE + relative_offset + size must not exceed page.
            let end = Self::HEADER_SIZE + usize::from(value_offset) + usize::from(value_size);
            if end > self.data.len() {
                return Err(EseError::RecordTooShort {
                    page: self.page_number,
                    tag: i,
                    got: self.data.len(),
                    need: end,
                });
            }
            tags.push((value_offset, value_size));
        }
        Ok(tags)
    }

    /// Return the raw data area of the page: bytes from the end of the 40-byte
    /// page header to the start of the tag array at the page end.
    ///
    /// This span contains ALL record bytes laid out sequentially, including bytes
    /// that may fall before the smallest tag offset (common in ESE's cumulative
    /// key-prefix-compression format).  Scanning this area directly (rather than
    /// individual tags) is the correct way to read real ESE catalog pages.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::Corrupt`] if the header cannot be parsed.
    pub fn raw_data_area(&self) -> Result<&[u8], EseError> {
        let hdr = self.parse_header()?;
        let tag_count = hdr.available_page_tag_count as usize;
        let tag_array_bytes = tag_count.saturating_mul(4);
        let tag_array_start = self.data.len().saturating_sub(tag_array_bytes);
        let start = Self::HEADER_SIZE.min(tag_array_start);
        Ok(&self.data[start..tag_array_start])
    }

    /// Return the raw record data slice for tag at `index`.
    ///
    /// Tag 0 is the page header tag. Data records start at tag 1.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::Corrupt`] if `index` is beyond the tag count, or
    /// [`EseError::RecordTooShort`] if the tag's data range is out of bounds.
    pub fn record_data(&self, index: usize) -> Result<&[u8], EseError> {
        let tags = self.tags()?;
        if index >= tags.len() {
            return Err(EseError::Corrupt {
                page: self.page_number,
                detail: format!("tag index {index} out of range (tag count: {})", tags.len()),
            });
        }
        let (offset, size) = tags[index];
        // Tag offsets are relative to the end of the 40-byte Vista+ page header.
        let start = Self::HEADER_SIZE + offset as usize;
        let end = start + size as usize;
        if end > self.data.len() {
            return Err(EseError::RecordTooShort {
                page: self.page_number,
                tag: index,
                got: self.data.len(),
                need: end,
            });
        }
        Ok(&self.data[start..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ese-page-header story ────────────────────────────────────────────────

    #[test]
    fn parse_header_page_flags_leaf() {
        let mut data = vec![0u8; 4096];
        // page_flags at offset 0x24 (Vista+)
        data[0x24..0x28].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());
        let page = EsePage {
            page_number: 1,
            data,
        };
        let hdr = page.parse_header().expect("parse header");
        assert_eq!(hdr.page_flags, PAGE_FLAG_LEAF);
        assert!(hdr.page_flags & PAGE_FLAG_LEAF != 0);
    }

    #[test]
    fn page_flag_constants_match_ese_spec() {
        assert_eq!(PAGE_FLAG_ROOT, 0x0001);
        assert_eq!(PAGE_FLAG_LEAF, 0x0002);
        assert_eq!(PAGE_FLAG_PARENT, 0x0004);
        assert_eq!(PAGE_FLAG_EMPTY, 0x0008);
        assert_eq!(PAGE_FLAG_SPACE_TREE, 0x0020);
        assert_eq!(PAGE_FLAG_LONG_VALUE, 0x0400);
    }

    #[test]
    fn parse_header_prev_next_links() {
        let mut data = vec![0u8; 4096];
        data[0x10..0x14].copy_from_slice(&5u32.to_le_bytes()); // prev_page = 5 (Vista+: 0x10)
        data[0x14..0x18].copy_from_slice(&7u32.to_le_bytes()); // next_page = 7 (Vista+: 0x14)
        let page = EsePage {
            page_number: 3,
            data,
        };
        let hdr = page.parse_header().expect("parse header");
        assert_eq!(hdr.prev_page, Some(5));
        assert_eq!(hdr.next_page, Some(7));
    }

    #[test]
    fn parse_header_none_when_0xffffffff() {
        let mut data = vec![0u8; 4096];
        data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // prev (Vista+: 0x10)
        data[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // next (Vista+: 0x14)
        let page = EsePage {
            page_number: 1,
            data,
        };
        let hdr = page.parse_header().expect("parse header");
        assert_eq!(hdr.prev_page, None);
        assert_eq!(hdr.next_page, None);
    }

    #[test]
    fn parse_header_short_buffer_returns_err() {
        let data = vec![0u8; 20]; // shorter than 40 bytes
        let page = EsePage {
            page_number: 1,
            data,
        };
        let result = page.parse_header();
        assert!(result.is_err(), "short buffer must return Err");
    }

    // ── Vista+ offset regression tests (real SRUDB.dat ground-truth) ─────────

    #[test]
    fn parse_header_tag_count_at_vista_offset_0x22() {
        // Vista+ page header: available_page_tag_count is at 0x22 (not 0x1E).
        // Writing 5 at 0x22 must be read back as 5; writing at 0x1E must NOT.
        let mut data = vec![0u8; 4096];
        data[0x22..0x24].copy_from_slice(&5u16.to_le_bytes());
        let page = EsePage {
            page_number: 1,
            data,
        };
        let hdr = page.parse_header().expect("parse header");
        assert_eq!(
            hdr.available_page_tag_count, 5,
            "tag count must be read from offset 0x22 per the Vista+ ESE format"
        );
    }

    #[test]
    fn parse_header_flags_at_vista_offset_0x24() {
        // Vista+ page header: page_flags is at 0x24 (not 0x20).
        let mut data = vec![0u8; 4096];
        data[0x24..0x28].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());
        let page = EsePage {
            page_number: 1,
            data,
        };
        let hdr = page.parse_header().expect("parse header");
        assert!(
            hdr.page_flags & PAGE_FLAG_LEAF != 0,
            "LEAF flag must be read from offset 0x24 per the Vista+ ESE format"
        );
    }

    #[test]
    fn parse_header_prev_next_at_vista_offsets_0x10_0x14() {
        // Vista+ page header: prev_page at 0x10, next_page at 0x14.
        let mut data = vec![0u8; 4096];
        data[0x10..0x14].copy_from_slice(&5u32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&9u32.to_le_bytes());
        let page = EsePage {
            page_number: 1,
            data,
        };
        let hdr = page.parse_header().expect("parse header");
        assert_eq!(hdr.prev_page, Some(5));
        assert_eq!(hdr.next_page, Some(9));
    }

    // ── ese-page-tags story ──────────────────────────────────────────────────

    /// Build a synthetic page with embedded data records.
    ///
    /// Layout:
    /// - Header (40 bytes) at absolute bytes 0-39
    /// - Records packed at absolute bytes 40+; tags store RELATIVE offsets (from header end)
    /// - Tag array at page end: tag[0] covers header, tags[1..] cover records
    fn make_page_with_records(page_size: usize, records: &[&[u8]]) -> Vec<u8> {
        const HEADER_SIZE: usize = 40;
        let mut d = vec![0u8; page_size];
        let tag_count = u16::try_from(1 + records.len()).unwrap_or(u16::MAX);
        // Vista+ header: tag_count at 0x22, PAGE_FLAG_LEAF at 0x24
        d[0x22..0x24].copy_from_slice(&tag_count.to_le_bytes());
        d[0x24..0x28].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());

        // Tag 0: relative offset=0, size=40 (covers the page header)
        write_tag(&mut d, page_size, 0, 0, 40);

        // Data records; tags store RELATIVE offsets (physical = HEADER_SIZE + relative)
        let mut cur_relative: u16 = 0;
        for (i, rec) in records.iter().enumerate() {
            let tag_idx = i + 1;
            let rec_size = u16::try_from(rec.len()).unwrap_or(u16::MAX);
            let absolute_start = HEADER_SIZE + usize::from(cur_relative);
            d[absolute_start..absolute_start + rec.len()].copy_from_slice(rec);
            write_tag(&mut d, page_size, tag_idx, cur_relative, rec_size);
            cur_relative += rec_size;
        }
        d
    }

    fn write_tag(page: &mut [u8], page_size: usize, tag_idx: usize, offset: u16, size: u16) {
        // Real ESE format: cb_ (size) in LOW 13 bits, ib_ (offset) in HIGH 13 bits.
        let raw: u32 = (u32::from(size) & 0x1FFF) | ((u32::from(offset) & 0x1FFF) << 16);
        let pos = page_size - (tag_idx + 1) * 4;
        page[pos..pos + 4].copy_from_slice(&raw.to_le_bytes());
    }

    #[test]
    fn tags_count_matches_header() {
        // 2 data records => tag_count = 3 (tag0 + 2 data tags)
        let data = make_page_with_records(4096, &[b"hello", b"world"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let tags = page.tags().expect("tags");
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn tags_first_record_offset_and_size() {
        let data = make_page_with_records(4096, &[b"AAAA", b"BBBB"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let tags = page.tags().expect("tags");
        // tag 1 is first data record; relative offset=0 (absolute=40), size=4
        assert_eq!(tags[1], (0, 4));
    }

    #[test]
    fn record_data_first_matches() {
        let data = make_page_with_records(4096, &[b"AAAA", b"BBBB"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let rec = page.record_data(1).expect("record 1");
        assert_eq!(rec, b"AAAA");
    }

    #[test]
    fn record_data_second_matches() {
        let data = make_page_with_records(4096, &[b"AAAA", b"BBBB"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let rec = page.record_data(2).expect("record 2");
        assert_eq!(rec, b"BBBB");
    }

    #[test]
    fn record_data_beyond_count_returns_err() {
        let data = make_page_with_records(4096, &[b"X", b"Y"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let result = page.record_data(5);
        assert!(result.is_err(), "index beyond tag count must return Err");
    }

    // ── real ESE tag field order (RED — cb_ in LOW bits, ib_ in HIGH bits) ──

    /// ESE TAG struct: low 13 bits = cb_ (SIZE), high 13 bits = ib_ (OFFSET).
    /// These two tests pin that contract against a page built with REAL ESE encoding.
    /// They will FAIL until `tags()` is fixed to read size from LOW and offset from HIGH.
    #[test]
    fn tags_real_ese_format_size_in_low_bits_offset_in_high_bits() {
        // raw = 4u32 means size=4 in LOW, offset=0 in HIGH (real ESE format).
        // Buggy code reads: offset=4 (LOW), size=0 (HIGH) → returns empty.
        // Fixed code reads: offset=0 (HIGH), size=4 (LOW) → returns sentinel.
        let mut data = vec![0u8; 4096];
        let sentinel = [0xDE, 0xAD, 0xBE, 0xEFu8];
        data[40..44].copy_from_slice(&sentinel); // HEADER_SIZE=40, offset=0

        data[0x22..0x24].copy_from_slice(&2u16.to_le_bytes()); // tag_count=2
        data[0x24..0x28].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // Tag 0: real ESE — size=40 in LOW, offset=0 in HIGH → 40u32
        data[4096 - 4..4096].copy_from_slice(&40u32.to_le_bytes());
        // Tag 1: real ESE — size=4 in LOW, offset=0 in HIGH → 4u32
        data[4096 - 8..4096 - 4].copy_from_slice(&4u32.to_le_bytes());

        let page = EsePage {
            page_number: 1,
            data,
        };
        let (tag_offset, tag_size) = page.tags().expect("tags")[1];
        assert_eq!(tag_size, 4, "cb_ (size) must be read from LOW 13 bits");
        assert_eq!(tag_offset, 0, "ib_ (offset) must be read from HIGH 13 bits");
        assert_eq!(
            page.record_data(1).expect("record_data"),
            &sentinel,
            "real ESE tag: size in LOW bits, offset in HIGH bits"
        );
    }

    #[test]
    fn record_data_real_ese_nonsequential_offset() {
        // Record 1 at offset=0, record 2 at offset=8 (non-sequential — 4-byte gap).
        // Direct access (offset+size per tag) must return correct bytes for both.
        let mut data = vec![0u8; 4096];
        let rec1 = [0xAAu8; 4];
        let rec2 = [0xBBu8; 4];
        data[40..44].copy_from_slice(&rec1); // HEADER_SIZE + offset=0
        data[48..52].copy_from_slice(&rec2); // HEADER_SIZE + offset=8

        data[0x22..0x24].copy_from_slice(&3u16.to_le_bytes()); // tag_count=3
        data[0x24..0x28].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // Tag 0: size=40, offset=0 → 40u32
        data[4096 - 4..4096].copy_from_slice(&40u32.to_le_bytes());
        // Tag 1: size=4, offset=0 → 4u32
        data[4096 - 8..4096 - 4].copy_from_slice(&4u32.to_le_bytes());
        // Tag 2: size=4, offset=8 → (8u32 << 16) | 4u32
        data[4096 - 12..4096 - 8].copy_from_slice(&((8u32 << 16) | 4u32).to_le_bytes());

        let page = EsePage {
            page_number: 1,
            data,
        };
        assert_eq!(
            page.record_data(1).expect("rec1"),
            &rec1,
            "record 1 at offset=0"
        );
        assert_eq!(
            page.record_data(2).expect("rec2"),
            &rec2,
            "record 2 at non-sequential offset=8"
        );
    }

    // ── tag offset relative-to-header story ──────────────────────────────────

    #[test]
    fn record_data_treats_tag_offset_as_relative_to_header_end() {
        // Per MS-ESEDB spec and libesedb/impacket: tag offsets are relative to
        // the END of the page header (byte 40 for Vista+ pages), not absolute
        // from page start.
        //
        // This test places sentinel bytes at absolute byte 42 (= HEADER_SIZE + 2)
        // and gives tag 1 a relative offset of 2. Correct behaviour: record_data(1)
        // returns the sentinel bytes. Wrong (absolute) behaviour: returns zeros
        // from within the 40-byte header at byte 2.
        let mut data = vec![0u8; 4096];
        let sentinel = [0xCA, 0xFE, 0xBA, 0xBEu8];
        // Place sentinel at absolute byte 42 = HEADER_SIZE(40) + relative_offset(2)
        data[42..46].copy_from_slice(&sentinel);

        let tag_count: u16 = 2;
        data[0x22..0x24].copy_from_slice(&tag_count.to_le_bytes());
        data[0x24..0x28].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        // Real ESE format: cb_ (size) in LOW bits, ib_ (offset) in HIGH bits.
        // Tag 0: size=40, offset=0 → raw = 40u32
        let tag0: u32 = 40u32;
        data[4096 - 4..4096].copy_from_slice(&tag0.to_le_bytes());

        // Tag 1: size=4, offset=2 → absolute bytes [42..46]
        let tag1: u32 = 4u32 | (2u32 << 16);
        data[4096 - 8..4096 - 4].copy_from_slice(&tag1.to_le_bytes());

        let page = EsePage {
            page_number: 1,
            data,
        };
        let rec = page.record_data(1).expect("record_data(1)");
        assert_eq!(
            rec, &sentinel,
            "record_data must add HEADER_SIZE(40) to tag offset; \
             relative offset 2 must read from absolute byte 42, not byte 2"
        );
    }
}
