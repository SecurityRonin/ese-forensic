//! ESE error types.

/// Errors that can occur when reading an ESE database.
#[derive(Debug, thiserror::Error)]
pub enum EseError {
    #[error("page {page}: invalid magic {found:#010x}")]
    InvalidMagic { page: u32, found: u32 },

    #[error("page {page} tag {tag}: record too short ({got} < {need})")]
    RecordTooShort {
        page: u32,
        tag: usize,
        got: usize,
        need: usize,
    },

    #[error("page {page}: tag array overflows page boundary")]
    TagArrayOverflow { page: u32 },

    #[error("table not found: {name}")]
    TableNotFound { name: String },

    #[error("page {page}: {detail}")]
    Corrupt { page: u32, detail: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ese_error_invalid_magic_display() {
        let err = EseError::InvalidMagic {
            page: 0,
            found: 0xDEAD_BEEF,
        };
        assert!(format!("{err}").contains("invalid magic"));
    }

    #[test]
    fn ese_error_record_too_short_display() {
        let err = EseError::RecordTooShort {
            page: 7,
            tag: 2,
            got: 10,
            need: 32,
        };
        assert!(format!("{err}").contains("record too short"));
        assert!(format!("{err}").contains("10 < 32"));
    }

    #[test]
    fn ese_error_tag_array_overflow_display() {
        let err = EseError::TagArrayOverflow { page: 5 };
        assert!(format!("{err}").contains("tag array"));
    }

    #[test]
    fn ese_error_table_not_found_display() {
        let err = EseError::TableNotFound {
            name: "MyTable".into(),
        };
        assert!(format!("{err}").contains("MyTable"));
    }

    #[test]
    fn ese_error_corrupt_display() {
        let err = EseError::Corrupt {
            page: 3,
            detail: "something bad".into(),
        };
        assert!(format!("{err}").contains("page 3"));
        assert!(format!("{err}").contains("something bad"));
    }
}
