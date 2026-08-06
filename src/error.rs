//! Error types for evbunpack-rs.
//!
//! Two primary error enums:
//! - [`EnigmaError`] — high-level errors: PE parsing, VFS walk, I/O.
//! - [`AplibError`]  — aPLib decompression errors.

use std::io;
use std::path::PathBuf;

/// Top-level result alias used throughout the library.
pub type Result<T> = std::result::Result<T, EnigmaError>;

/// Errors raised while parsing the PE container or the Enigma VFS.
#[derive(thiserror::Error, Debug)]
pub enum EnigmaError {
    #[error("invalid EVB magic signature")]
    InvalidMagic,

    #[error("invalid PE image")]
    InvalidPe,

    #[error("missing required PE section: {0}")]
    NoEnigmaSection(String),

    #[error("unexpected end of input")]
    UnexpectedEof,

    #[error("VFS parse error: {0}")]
    VfsParse(String),

    #[error("PE restore error: {0}")]
    PeRestore(String),

    #[error("invalid node name: {0}")]
    InvalidNodeName(String),

    #[error("I/O error reading {0}")]
    Io(#[from] io::Error),

    #[error("path error: {0}")]
    Path(#[from] std::path::StripPrefixError),

    #[error("file does not exist: {0}")]
    FileNotFound(PathBuf),
}

/// Errors raised by the aPLib decompressor.
#[derive(thiserror::Error, Debug)]
pub enum AplibError {
    #[error("invalid aPLib header")]
    InvalidHeader,

    #[error("packed data CRC mismatch")]
    PackedCrcMismatch,

    #[error("unexpected end of compressed stream")]
    UnexpectedEof,

    #[error("invalid back-reference offset")]
    InvalidOffset,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl From<AplibError> for EnigmaError {
    /// Promote an aPLib error into a VFS parse error so callers that only care
    /// about the high-level pipeline can `?` it through.
    fn from(e: AplibError) -> Self {
        EnigmaError::VfsParse(format!("aPLib: {e}"))
    }
}
