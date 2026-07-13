//! ESE page carving and fragmented record reconstruction.
//!
//! Detects records split across page boundaries ([`detect_fragments`]) and
//! stitches them back together ([`reconstruct_fragment`]).
//!
//! These are raw binary operations — forensic interpretation belongs in the
//! `RapidTriage` correlation layer.

/// A pair of page indices where a record is split across a page boundary.
///
/// `page_a` holds the record prefix (last tag of that page) and `page_b`
/// holds the record suffix (first data tag of that page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentPair {
    /// 1-based page number of the page containing the record prefix.
    pub page_a: u32,
    /// 1-based page number of the page containing the record suffix.
    pub page_b: u32,
    /// Byte length of the prefix (last tag of `page_a`).
    pub prefix_len: usize,
    /// Byte length of the suffix (first data tag of `page_b`).
    pub suffix_len: usize,
}

/// Scan an open ESE database for records split across consecutive page
/// boundaries.
///
/// Returns a [`FragmentPair`] for every adjacent page pair where the last tag
/// of page N and the first data tag (tag 1) of page N+1 together equal
/// `expected_size`. Pages are iterated from 1 to `page_count - 2` (page 0 is
/// the file header and is skipped; the last page has no successor to pair with).
pub fn detect_fragments_db(db: &ese_core::EseDatabase, expected_size: usize) -> Vec<FragmentPair> {
    let page_count = u32::try_from(db.page_count()).unwrap_or(u32::MAX);
    let mut pairs = Vec::new();

    for page_idx in 1..page_count.saturating_sub(1) {
        let Ok(page_a) = db.read_page(page_idx) else {
            continue;
        };
        let Ok(page_b) = db.read_page(page_idx + 1) else {
            continue;
        };
        let Ok(tags_a) = page_a.tags() else { continue };
        let Ok(tags_b) = page_b.tags() else { continue };

        // Last tag of page A = potential prefix fragment
        let Some(&(_, prefix_size)) = tags_a.last() else {
            continue;
        };
        // First *data* tag of page B (tag 1; tag 0 is the page header)
        let Some(&(_, suffix_size)) = tags_b.get(1) else {
            continue;
        };

        let prefix_len = prefix_size as usize;
        let suffix_len = suffix_size as usize;

        if prefix_len + suffix_len == expected_size {
            pairs.push(FragmentPair {
                page_a: page_idx,
                page_b: page_idx + 1,
                prefix_len,
                suffix_len,
            });
        }
    }
    pairs
}

/// Scan a flat byte slice for records split across consecutive page boundaries.
///
/// This is the raw-bytes variant; prefer [`detect_fragments_db`] when an open
/// [`ese_core::EseDatabase`] is available.
///
/// `pages` must be a multiple of `page_size` bytes. Pages are numbered from 1
/// (page 0 is the file header and is skipped).
pub fn detect_fragments(pages: &[u8], page_size: usize, expected_size: usize) -> Vec<FragmentPair> {
    if page_size == 0 || pages.len() % page_size != 0 {
        return vec![];
    }
    let total_pages = pages.len() / page_size;
    let mut pairs = Vec::new();

    for page_idx in 1..total_pages.saturating_sub(1) {
        let a_start = page_idx * page_size;
        let b_start = (page_idx + 1) * page_size;
        let page_a = &pages[a_start..a_start + page_size];
        let page_b = &pages[b_start..b_start + page_size];

        let Some(tags_a) = parse_tags_raw(page_a, page_size) else {
            continue;
        };
        let Some(tags_b) = parse_tags_raw(page_b, page_size) else {
            continue;
        };

        let Some(&(_, prefix_len)) = tags_a.last() else {
            continue;
        };
        let Some(&(_, suffix_len)) = tags_b.get(1) else {
            continue;
        };

        if prefix_len + suffix_len == expected_size {
            pairs.push(FragmentPair {
                page_a: u32::try_from(page_idx).unwrap_or(u32::MAX),
                page_b: u32::try_from(page_idx + 1).unwrap_or(u32::MAX),
                prefix_len,
                suffix_len,
            });
        }
    }
    pairs
}

fn parse_tags_raw(page: &[u8], page_size: usize) -> Option<Vec<(usize, usize)>> {
    if page.len() < page_size || page_size < 0x28 {
        return None;
    }
    // Vista+ header: available_page_tag_count at 0x22 (0x1E in pre-Vista format).
    let tag_count = u16::from_le_bytes([page[0x22], page[0x23]]) as usize;
    if tag_count == 0 {
        return None;
    }
    let mut tags = Vec::with_capacity(tag_count);
    for i in 0..tag_count {
        let pos = page_size - (i + 1) * 4;
        let raw = u32::from_le_bytes([page[pos], page[pos + 1], page[pos + 2], page[pos + 3]]);
        // Real ESE: cb_ (size) in LOW 13 bits, ib_ (offset) in HIGH 13 bits.
        tags.push((((raw >> 16) & 0x1FFF) as usize, (raw & 0x1FFF) as usize));
    }
    Some(tags)
}

/// Reconstruct a fragmented record from a prefix and suffix slice.
///
/// Returns the stitched bytes if `prefix.len() + suffix.len() == expected_size`,
/// `None` otherwise.
pub fn reconstruct_fragment(prefix: &[u8], suffix: &[u8], expected_size: usize) -> Option<Vec<u8>> {
    if prefix.len() + suffix.len() != expected_size {
        return None;
    }
    let mut out = Vec::with_capacity(expected_size);
    out.extend_from_slice(prefix);
    out.extend_from_slice(suffix);
    Some(out)
}
