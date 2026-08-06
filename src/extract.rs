//! High-level VFS extraction driver.
use std::path::{Path, PathBuf};

use crate::enigma;
use crate::error::{EnigmaError, Result};

/// Alternate folder names that should be normalized away (root of the tree).
#[allow(dead_code)]
fn normalize_folder_name(name: &str) -> String {
    match name {
        "%DEFAULT FOLDER%" => String::new(),
        _ => name.to_string(),
    }
}

/// Validate a node name the same way the Python implementation does: reject
/// path separators, drive separators, and path-traversal segments.
fn validate_node_name(name: &str) -> Result<()> {
    if name.contains('/') || name.contains('\\') || name.contains(':') {
        return Err(EnigmaError::InvalidNodeName(name.to_string()));
    }
    if name == ".." || name == "." {
        return Err(EnigmaError::InvalidNodeName(name.to_string()));
    }
    Ok(())
}

/// Configuration for an extraction run.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub out_dir: PathBuf,
    /// If true, only print the directory listing; do not write any files.
    pub list_only: bool,
    /// If true, use the legacy in-place VFS tree layout (`legacy_pe_tree`).
    pub legacy_fs: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("."),
            list_only: false,
            legacy_fs: false,
        }
    }
}

/// Extract the Enigma Virtual Box VFS from `input`, writing files under
/// `opts.out_dir` (unless `opts.list_only`). Returns the number of files
/// written / listed.
pub fn extract(input: &Path, opts: &ExtractOptions) -> Result<usize> {
    // Reuse the existing high-level `unpack` driver for the default (PE-external)
    // layout. Legacy layout support is tracked separately once `legacy_pe_tree`
    // is implemented in `enigma::records`.
    if opts.legacy_fs {
        tracing::warn!("legacy VFS layout is not yet implemented; falling back to default");
    }

    let files = enigma::unpack(input)?;

    // Print the tree (always, to mirror Python output which prints the listing
    // even when only listing).
    eprintln!("Filesystem:");
    print_tree(&files, &opts.out_dir);
    tracing::debug!("matched {} VFS entries", files.len());

    if opts.list_only {
        return Ok(files.len());
    }

    let mut written = 0usize;
    for file in &files {
        validate_node_name(&file.path)?;
        let dest = opts.out_dir.join(&file.path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &file.data)?;
        written += 1;
    }
    tracing::info!("wrote {} files to {}", written, opts.out_dir.display());
    Ok(written)
}

/// Print a rudimentary ASCII tree of the extracted entries to stderr.
///
/// This is intentionally simpler than the Python `├───` rendering; it lists
/// one path per line under the output dir so the structure is still legible.
fn print_tree(files: &[enigma::ExtractedFile], out_dir: &Path) {
    for file in files {
        eprintln!("    {}/{}", out_dir.display(), file.path);
    }
}
