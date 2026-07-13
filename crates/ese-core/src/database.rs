//! ESE database handle for page-level access.

use std::path::{Path, PathBuf};

use memmap2::Mmap;

use crate::{catalog::CatalogEntry, record::ColumnDef, EseError, EseHeader, EsePage};

/// Iterator over raw record bytes across all leaf pages of a B-tree.
///
/// Each item is `(page_number, tag_index, record_bytes)`.
///
/// Record bytes are read directly from each tag's `(offset, size)` pair:
/// `page.data[HEADER_SIZE + offset .. HEADER_SIZE + offset + size]`.
/// This is correct for SRUM data tables, which store independently-addressed
/// records rather than key-prefix-compressed B-tree index keys.
///
/// Error recovery: if a page cannot be read or its tag array is corrupt,
/// the error is yielded and the iterator advances to the next page.
#[derive(Debug)]
pub struct TableCursor<'db> {
    db: &'db EseDatabase,
    leaf_pages: Vec<u32>,
    page_idx: usize,
    tag_idx: usize, // starts at 1 (tag 0 is the page header tag)
}

impl Iterator for TableCursor<'_> {
    type Item = Result<(u32, usize, Vec<u8>), EseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let &page_num = self.leaf_pages.get(self.page_idx)?;
            let page = match self.db.read_page(page_num) {
                Ok(p) => p,
                Err(e) => {
                    self.page_idx += 1;
                    self.tag_idx = 1;
                    return Some(Err(e));
                }
            };
            let tags = match page.tags() {
                Ok(t) => t,
                Err(e) => {
                    self.page_idx += 1;
                    self.tag_idx = 1;
                    return Some(Err(e));
                }
            };
            if self.tag_idx >= tags.len() {
                self.page_idx += 1;
                self.tag_idx = 1;
                continue;
            }
            let tag_idx = self.tag_idx;
            self.tag_idx += 1;

            let (tag_off, tag_sz) = tags[tag_idx];
            if tag_sz == 0 {
                continue; // skip zero-length tags
            }
            let start = page
                .value_data_offset()
                .saturating_add(usize::from(tag_off));
            let end = start.saturating_add(usize::from(tag_sz));
            if end > page.data.len() {
                return Some(Err(EseError::Corrupt {
                    page: page_num,
                    detail: format!(
                        "tag {tag_idx} out of bounds (offset={tag_off}, size={tag_sz}, \
                         page_len={})",
                        page.data.len()
                    ),
                }));
            }
            let raw = &page.data[start..end];
            // On the extended (large-page) format, leaf entries are B-tree
            // key-prefixed; strip the key and skip defunct entries so callers
            // receive clean data-definition records that match esedbexport.
            if self.db.is_extended_format() {
                match crate::record::leaf_entry_data(raw, true) {
                    Some(record) => return Some(Ok((page_num, tag_idx, record.to_vec()))),
                    None => continue, // defunct or malformed — skip
                }
            }
            return Some(Ok((page_num, tag_idx, raw.to_vec())));
        }
    }
}

/// An open ESE database file, memory-mapped for zero-copy page access.
///
/// The file is mapped once at [`open`][EseDatabase::open] time. All subsequent
/// [`read_page`][EseDatabase::read_page] and [`raw_page_slice`][EseDatabase::raw_page_slice]
/// calls slice directly into the mapping — no additional syscalls or heap
/// allocations per page.
///
/// # Safety invariant
///
/// The mapping is read-only. Callers must not modify the file on disk while an
/// `EseDatabase` is live; doing so is undefined behaviour (per `memmap2` docs).
/// In practice SRUDB.dat is treated as forensic evidence and never written.
pub struct EseDatabase {
    path: PathBuf,
    /// Parsed file header.
    pub header: EseHeader,
    mmap: Mmap,
}

impl std::fmt::Debug for EseDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EseDatabase")
            .field("path", &self.path)
            .field("header", &self.header)
            .field("mmap_len", &self.mmap.len())
            .finish()
    }
}

impl EseDatabase {
    /// Open an ESE database at `path` and memory-map the entire file.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if the file cannot be opened, mapped, or is not a
    /// valid ESE database.
    pub fn open(path: &Path) -> Result<Self, EseError> {
        let file = std::fs::File::open(path)?;
        // SAFETY: the mapped file is read-only forensic evidence; we never write
        // to it while this mapping is live, so the UB precondition cannot trigger.
        #[allow(unsafe_code)]
        let mmap = unsafe { Mmap::map(&file) }?;
        let header = EseHeader::from_bytes(&mmap)?;
        Ok(Self {
            path: path.to_owned(),
            header,
            mmap,
        })
    }

    /// Return a zero-copy slice of the raw bytes for page `page_number`.
    ///
    /// The slice borrows directly from the memory mapping — no heap allocation.
    /// Returns [`EseError::Corrupt`] if `page_number` is beyond the end of the
    /// file.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if the requested page is out of range.
    pub fn raw_page_slice(&self, page_number: u32) -> Result<&[u8], EseError> {
        let page_size = self.header.page_size as usize;
        let start = usize::try_from(page_number)
            .unwrap_or(usize::MAX)
            .saturating_mul(page_size);
        let end = start.saturating_add(page_size);
        if end > self.mmap.len() {
            return Err(EseError::Corrupt {
                page: page_number,
                detail: format!(
                    "page beyond file end: need offset {end}, file is {} bytes",
                    self.mmap.len()
                ),
            });
        }
        Ok(&self.mmap[start..end])
    }

    /// Read a single page by its 0-based page number.
    ///
    /// Page 0 is the header page. Data pages start at page 1.
    /// Returns [`EseError::Corrupt`] if `page_number` is beyond the file.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] on I/O error or if the page is out of range.
    pub fn read_page(&self, page_number: u32) -> Result<EsePage, EseError> {
        Ok(EsePage {
            page_number,
            data: self.raw_page_slice(page_number)?.to_vec(),
        })
    }

    /// Return the total number of pages in the file (including the header page).
    pub fn page_count(&self) -> u64 {
        u64::try_from(self.mmap.len()).unwrap_or(0) / u64::from(self.header.page_size)
    }

    /// Read and parse all entries from the ESE catalog (physical page 5).
    ///
    /// The catalog (`MSysObjects`) maps table names to their root B-tree page
    /// numbers. Physical page 5 is the catalog root in real SRUDB.dat files
    /// (fdp=2, ROOT|PARENT or ROOT|LEAF).
    ///
    /// Each tag on the catalog leaf pages (tags 1+, skipping tag 0) is first
    /// tried against the real ESE tagged-column format via
    /// [`CatalogEntry::parse_real_catalog_record`], then against the synthetic
    /// fixture format via [`CatalogEntry::from_bytes`] as a fallback.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if the catalog page cannot be read or contains
    /// malformed records.
    pub fn catalog_entries(&self) -> Result<Vec<CatalogEntry>, EseError> {
        const CATALOG_ROOT: u32 = 5; // physical page 5 = ESE catalog root (fdp=2)
        let extended = self.is_extended_format();
        let leaf_pages = self.walk_leaf_pages(CATALOG_ROOT)?;
        // Dedup by (object_type, parent_object_id, object_id) — NOT by name.
        // Keying by name globally collapses columns that different tables share
        // (every WebCache Container_# has `Url`, `AccessedTime`, ...). The tuple
        // is unique per catalog object, so each table keeps its own columns.
        //
        // Last-wins on that key still handles the SRUDB.dat case of a placeholder
        // object registered before the live one with the same identity: walking
        // the B-tree in key order, the live entry sits on a later leaf and wins.
        let mut by_key: std::collections::HashMap<(u16, u32, u32), CatalogEntry> =
            std::collections::HashMap::default();
        let mut insert = |e: CatalogEntry| {
            by_key.insert((e.object_type, e.parent_object_id, e.object_id), e);
        };
        for page_num in leaf_pages {
            let page = self.read_page(page_num)?;
            if extended {
                // Real MSysObjects: each leaf entry (tags 1.., value 0 skipped) is
                // a key-prefixed data-definition record; strip the key, skip
                // defunct entries, and decode tables + columns.
                let tag_count = page.tags()?.len();
                for i in 1..tag_count {
                    let value = page.record_data(i)?;
                    let Some(record) = crate::record::leaf_entry_data(value, true) else {
                        continue; // defunct or malformed
                    };
                    if let Some(entry) = CatalogEntry::decode_catalog_record(record) {
                        insert(entry);
                    }
                }
            } else {
                // Synthetic / legacy small-page fixtures: scan the raw data area
                // for real \xff\x00 records, else parse the fixed-layout format.
                let real_entries = CatalogEntry::scan_catalog_page_data(page.raw_data_area()?);
                if real_entries.is_empty() {
                    let tags = page.tags()?;
                    for i in 1..tags.len() {
                        let data = page.record_data(i)?;
                        if let Some(entry) = CatalogEntry::parse_real_catalog_record(data) {
                            insert(entry);
                        } else if let Ok(entry) = CatalogEntry::from_bytes(data) {
                            insert(entry);
                        }
                    }
                } else {
                    for entry in real_entries {
                        insert(entry);
                    }
                }
            }
        }
        Ok(by_key.into_values().collect())
    }

    /// Whether this database uses the large-page extended format (page size of
    /// 16384 or 32768, format revision 17+): tag offsets past a 40-byte extended
    /// page header, key-prefixed leaf entries, and tagged-column records.
    #[must_use]
    pub fn is_extended_format(&self) -> bool {
        self.header.page_size >= 16384
    }

    /// Walk the B-tree rooted at `root_page` and return the page numbers of
    /// all leaf pages.
    ///
    /// - If the page has [`PAGE_FLAG_LEAF`][crate::PAGE_FLAG_LEAF] set, it is
    ///   returned directly.
    /// - Otherwise each tag (skipping tag 0) is treated as a parent-node
    ///   reference: the child page ESE number is stored in the **last 4 bytes**
    ///   of the tag data (after any B-tree key prefix).  The physical page is
    ///   `stored_value + 1` (ESE uses 0-based data-page numbering, offset by
    ///   the file-header page).
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if any page cannot be read or parsed.
    pub fn walk_leaf_pages(&self, root_page: u32) -> Result<Vec<u32>, EseError> {
        let mut leaves = Vec::new();
        let mut visited = std::collections::HashSet::new();
        self.walk_leaf_pages_inner(root_page, &mut leaves, &mut visited, 0)?;
        Ok(leaves)
    }

    /// Recursive worker for [`walk_leaf_pages`].
    ///
    /// `visited` breaks child-pointer cycles and `depth` caps the recursion, so
    /// a malformed (attacker-controllable) B-tree cannot loop or blow the stack.
    fn walk_leaf_pages_inner(
        &self,
        page_number: u32,
        leaves: &mut Vec<u32>,
        visited: &mut std::collections::HashSet<u32>,
        depth: u32,
    ) -> Result<(), EseError> {
        // ESE B-trees are shallow; 64 levels is far beyond any real database and
        // bounds recursion on hostile input.
        const MAX_DEPTH: u32 = 64;
        if depth >= MAX_DEPTH || !visited.insert(page_number) {
            return Ok(());
        }
        let page = self.read_page(page_number)?;
        let hdr = page.parse_header()?;
        if hdr.page_flags & crate::PAGE_FLAG_LEAF != 0 {
            leaves.push(page_number);
            return Ok(());
        }
        // Parent (or root) page: the child page reference is the LAST 4 bytes of
        // each branch entry (after the common/local B-tree key). The tag count
        // comes from `tags()`, whose masked length is authoritative on large
        // pages (the raw header field carries flag bits in its top nibble).
        let page_count = self.page_count();
        let tag_count = page.tags()?.len();
        for i in 1..tag_count {
            let data = page.record_data(i)?;
            // Read the trailing u32 through a bounds-checked slice so a record
            // shorter than 4 bytes is skipped, never a panic.
            let Some(child_bytes) = data.get(data.len().saturating_sub(4)..) else {
                continue; // cov:unreachable: data.len()-4 clamps to 0, slice always valid
            };
            if child_bytes.len() < 4 {
                continue;
            }
            let child_ese = u32::from_le_bytes([
                child_bytes[0],
                child_bytes[1],
                child_bytes[2],
                child_bytes[3],
            ]);
            let child_page = child_ese.saturating_add(1); // ESE 0-based → physical page
                                                          // Skip references outside the file rather than erroring: a single
                                                          // bad branch pointer must not abort the whole walk.
            if u64::from(child_page) >= page_count {
                continue;
            }
            self.walk_leaf_pages_inner(child_page, leaves, visited, depth + 1)?;
        }
        Ok(())
    }

    /// Find the root B-tree page number for the named table.
    ///
    /// Reads the catalog and returns the `table_page` of the first entry
    /// whose `object_name` matches `name`.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::TableNotFound`] if no matching table is in the catalog,
    /// or any I/O / parse error from [`catalog_entries`][Self::catalog_entries].
    pub fn find_table_page(&self, name: &str) -> Result<u32, EseError> {
        let entries = self.catalog_entries()?;
        entries
            .iter()
            .find(|e| e.object_name == name)
            .map(|e| e.table_page)
            .ok_or_else(|| EseError::TableNotFound {
                name: name.to_owned(),
            })
    }

    /// Open a cursor over all leaf records starting at `root_page`.
    ///
    /// # Errors
    ///
    /// Returns [`EseError`] if the leaf pages cannot be walked from `root_page`.
    pub fn table_records_from_root(&self, root_page: u32) -> Result<TableCursor<'_>, EseError> {
        let leaf_pages = self.walk_leaf_pages(root_page)?;
        Ok(TableCursor {
            db: self,
            leaf_pages,
            page_idx: 0,
            tag_idx: 1,
        })
    }

    /// Return the column definitions for a named table from the catalog.
    ///
    /// Reads the catalog, finds the table entry (`object_type` 1) whose name
    /// matches `table_name`, then collects all column entries (`object_type` 2)
    /// whose `parent_object_id` equals the table's `object_id`. In the
    /// synthetic catalog format, column entries store the JET coltyp in the
    /// `table_page` field. Results are sorted ascending by `column_id`.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::TableNotFound`] if `table_name` is not in the
    /// catalog, or any I/O / parse error from [`catalog_entries`][Self::catalog_entries].
    pub fn table_columns(&self, table_name: &str) -> Result<Vec<ColumnDef>, EseError> {
        let entries = self.catalog_entries()?;
        let table = entries
            .iter()
            .find(|e| e.object_type == 1 && e.object_name == table_name)
            .ok_or_else(|| EseError::TableNotFound {
                name: table_name.to_owned(),
            })?;
        let table_obj_id = table.object_id;
        let mut cols: Vec<ColumnDef> = entries
            .iter()
            .filter(|e| e.object_type == 2 && e.parent_object_id == table_obj_id)
            .map(|e| ColumnDef {
                column_id: e.object_id,
                name: e.object_name.clone(),
                coltyp: e.table_page as u8,
            })
            .collect();
        cols.sort_by_key(|c| c.column_id);
        Ok(cols)
    }

    /// Open a cursor over all records in a named SRUM table.
    ///
    /// Returns `Err(EseError::TableNotFound)` immediately if the table is absent.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::TableNotFound`] if `table_name` is not in the catalog,
    /// or any I/O / parse error from reading the catalog or walking leaf pages.
    pub fn table_records(&self, table_name: &str) -> Result<TableCursor<'_>, EseError> {
        let root_page = self.find_table_page(table_name)?;
        self.table_records_from_root(root_page)
    }
}
