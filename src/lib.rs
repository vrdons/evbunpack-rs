//! evbunpack-rs — Enigma Virtual Box unpacker, Rust port of `evbunpack` (Python).
//!
//! This crate is the **library** surface; the command-line binary lives in
//! the workspace member `cli/` so that CLI-only dependencies (`clap`,
//! `tracing-subscriber`) are not pulled in by dependents of this library.
//!
//! Library layout:
//! - [`enigma`]     — PE parser, VFS records walker, aPLib decompressor.
//! - [`pe_restore`] — restore the original executable from `.enigma1`.
//! - [`extract`]    — high-level VFS extraction driver (mirrors `unpack_files`).
//! - [`error`]      — typed error enums.

pub mod enigma;
pub mod error;
pub mod extract;
pub mod pe_restore;

pub use error::{AplibError, EnigmaError, Result};
