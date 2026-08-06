//! PE restoration — port of `restore_pe()` from the Python reference.
//!
//! Reads the `.enigma1` section header to recover the original PE's Import,
//! Reloc, Exception, and TLS data directories, and removes the `.enigma1` /
//! `.enigma2` loader sections.
//!
//! NOTE: This is the largest and most intricate port. The current
//! [`restore_pe`] implementation focuses on the structural steps that are
//! feasible with `goblin`'s read-only PE view plus raw byte editing; the
//! Exception-directory relocation and TLS scan are best-effort and may emit
//! warnings on unusual inputs (matching the Python behavior).

use std::path::Path;

use goblin::pe::PE;

use crate::error::{EnigmaError, Result};

/// Restored PE header fields read from `.enigma1`.
#[derive(Debug, Clone, Default)]
pub struct Enigma1Header {
    pub import_address: u32,
    pub import_size: u32,
    pub reloc_address: u32,
    pub reloc_size: u32,
    pub tls_address: u32,
    pub tls_size: u32,
    /// Raw TLS directory blob copied into the header (16s/32s in Python).
    pub tls: Vec<u8>,
}

/// Layout descriptor for a `(arch, variant)` header family.
///
/// Each field is an absolute offset within `.enigma1` for that field. Offsets
/// are derived from the struct tables in `const.py::EVB_ENIGMA1_HEADER`.
struct VariantLayout {
    tls_len: usize,
    import_addr_off: usize,
    import_size_off: usize,
    reloc_addr_off: usize,
    reloc_size_off: usize,
    tls_addr_off: usize,
    tls_size_off: usize,
}

/// Resolve the byte layout for `(arch, variant)` from the Python struct tables.
///
/// Offsets are verified against `const.py::EVB_ENIGMA1_HEADER` (each struct is a
/// TLS blob, then padding Qs / UNK fields, then six contiguous u32 fields
/// IMPORT_ADDR, IMPORT_SIZE, RELOC_ADDR, RELOC_SIZE, TLS_ADDR, TLS_SIZE).
fn layout_for(is_64bit: bool, variant: &str) -> Result<VariantLayout> {
    let (tls_len, import_addr_off) = match (is_64bit, variant) {
        (true, "10_70") => (32usize, 120usize),
        (true, "9_70") => (32, 108),
        (true, "7_80") => (32, 104),
        (false, "10_70") => (16, 84),
        (false, "9_70") => (16, 80),
        (false, "7_80") => (16, 76),
        _ => {
            return Err(EnigmaError::PeRestore(format!(
                "unknown PE variant '{variant}' for arch {}",
                if is_64bit { "x64" } else { "x86" }
            )));
        }
    };
    Ok(VariantLayout {
        tls_len,
        import_addr_off,
        import_size_off: import_addr_off + 4,
        reloc_addr_off: import_addr_off + 8,
        reloc_size_off: import_addr_off + 12,
        tls_addr_off: import_addr_off + 16,
        tls_size_off: import_addr_off + 20,
    })
}

fn rd_u32(buf: &[u8], off: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        buf.get(off..off + 4)
            .ok_or(EnigmaError::UnexpectedEof)?
            .try_into()
            .unwrap(),
    ))
}

/// Parse the `.enigma1` header using the layout for `(is_64bit, variant)`.
pub fn parse_enigma1_header(
    enigma1: &[u8],
    is_64bit: bool,
    variant: &str,
) -> Result<Enigma1Header> {
    let lay = layout_for(is_64bit, variant)?;
    if enigma1.len() < lay.tls_size_off + 4 {
        return Err(EnigmaError::UnexpectedEof);
    }
    Ok(Enigma1Header {
        tls: enigma1[..lay.tls_len].to_vec(),
        import_address: rd_u32(enigma1, lay.import_addr_off)?,
        import_size: rd_u32(enigma1, lay.import_size_off)?,
        reloc_address: rd_u32(enigma1, lay.reloc_addr_off)?,
        reloc_size: rd_u32(enigma1, lay.reloc_size_off)?,
        tls_address: rd_u32(enigma1, lay.tls_addr_off)?,
        tls_size: rd_u32(enigma1, lay.tls_size_off)?,
    })
}

/// Data directory entry indices in the PE Optional Header.
const DIR_IMPORT: usize = 1;
const DIR_RELOC: usize = 5;
const DIR_EXCEPTION: usize = 3;
const DIR_TLS: usize = 9;

/// Owned section-record snapshot. We extract everything we need from goblin's
/// view up front so the `&raw` borrow via `PE::parse` is released before we
/// mutate `raw`.
#[derive(Debug, Clone, Copy)]
struct SecInfo {
    virtual_address: u32,
    raw_offset: u32,
    raw_size: u32,
}

/// Restore the original executable present inside `input` and write the result
/// to `output`. `variant` selects the `.enigma1` header layout.
pub fn restore_pe(input: &Path, output: &Path, variant: &str) -> Result<()> {
    let mut raw = std::fs::read(input)?;

    // --- Phase 1: read-only parse. Extract everything we need, then drop `pe`. ---
    let (is_64bit, sections, _enigma1_start, hdr) = {
        let pe = PE::parse(&raw).map_err(|e| EnigmaError::PeRestore(format!("PE parse: {e}")))?;
        let is_64bit = pe.is_64;
        tracing::debug!("PE loaded. Arch={}", if is_64bit { "x64" } else { "x86" });
        tracing::info!("Unpacking with variant: {variant}");

        // Snapshot section table into owned structs.
        let sections: Vec<SecInfo> = pe
            .sections
            .iter()
            .map(|s| SecInfo {
                virtual_address: s.virtual_address,
                raw_offset: s.pointer_to_raw_data,
                raw_size: s.size_of_raw_data,
            })
            .collect();

        // Locate .enigma1 by name to get its raw file offset.
        let mut enigma1_raw_off = None;
        for (i, s) in pe.sections.iter().enumerate() {
            let name = s.name().unwrap_or("");
            if name.starts_with(".enigma1") {
                enigma1_raw_off = Some(pe.sections[i].pointer_to_raw_data as usize);
                break;
            }
        }
        let enigma1_start = enigma1_raw_off.ok_or_else(|| {
            EnigmaError::PeRestore(
                "Cannot find .enigma1 section. The file is likely not packed with Enigma Virtual Box, \
                 or has obfuscated section names."
                    .into(),
            )
        })?;

        let hdr = parse_enigma1_header(&raw[enigma1_start..], is_64bit, variant)?;
        (is_64bit, sections, enigma1_start, hdr)
    };
    // `pe` is now dropped; `raw` is free to mutate.

    if hdr.reloc_size == 0 || hdr.import_size == 0 {
        tracing::warn!(
            "Import/Reloc table size is zero. This may indicate that the header is incorrectly parsed."
        );
    }
    tracing::debug!(
        "Import -> VA=0x{:x} Size=0x{:x}",
        hdr.import_address,
        hdr.import_size
    );
    tracing::debug!(
        "Reloc  -> VA=0x{:x} Size=0x{:x}",
        hdr.reloc_address,
        hdr.reloc_size
    );

    // --- Phase 2: locate the two .enigma* section indices from the snapshot. ---
    // They are the last two sections per Enigma packing order.
    let last = sections.len();
    if last < 2 {
        return Err(EnigmaError::PeRestore(
            "PE has fewer than 2 sections; cannot find .enigma2".into(),
        ));
    }
    let enigma1_idx = last - 2;
    let enigma2_idx = last - 1;
    let enigma1_raw_off = sections[enigma1_idx].raw_offset as usize;
    let enigma2_raw_off = sections[enigma2_idx].raw_offset as usize;
    let enigma2_raw_size = sections[enigma2_idx].raw_size as usize;

    // --- Phase 3: patch data directories in the raw buffer. ---
    patch_data_directory(
        &mut raw,
        is_64bit,
        DIR_IMPORT,
        hdr.import_address,
        hdr.import_size,
    )?;
    patch_data_directory(
        &mut raw,
        is_64bit,
        DIR_RELOC,
        hdr.reloc_address,
        hdr.reloc_size,
    )?;

    // Exception directory rebuild: trim entries until one falls into an
    // .enigma* section, then optionally relocate into a zero-run. We only trim
    // the directory size and clear the entry on this best-effort pass; a full
    // relocation needs section-relative writes that are documented in the
    // Python reference.
    patch_data_directory(&mut raw, is_64bit, DIR_EXCEPTION, 0, 0)?;
    tracing::debug!("Exception directory cleared (best-effort)");

    // TLS directory: try to find the header TLS blob verbatim in the surviving
    // sections and point the directory at it. If not found, zero it out.
    // Python searches only the first 12 bytes of the TLS blob (`tls_data[:12]`).
    let tls_needle = if hdr.tls.len() >= 12 {
        &hdr.tls[..12]
    } else {
        &hdr.tls[..]
    };
    if let Some(rva) = find_bytes_rva(&raw, &sections, tls_needle, enigma1_idx, enigma2_idx) {
        let tls_size = if is_64bit { 40u32 } else { 24u32 };
        patch_data_directory(&mut raw, is_64bit, DIR_TLS, rva, tls_size)?;
        tracing::debug!("TLS Directory found. RVA=0x{:x}", rva);
    } else {
        patch_data_directory(&mut raw, is_64bit, DIR_TLS, 0, 0)?;
        tracing::debug!(
            "TLS Directory not found. Original program probably does not have TLS data."
        );
    }

    // --- Phase 4: remove .enigma1 / .enigma2 raw bytes (preserve overlay). ---
    let cut_lo = enigma1_raw_off;
    let cut_hi = enigma2_raw_off + enigma2_raw_size;
    if cut_lo < cut_hi && cut_hi <= raw.len() {
        raw.drain(cut_lo..cut_hi);
    }

    // Patch the section table: zero out the .enigma1 / .enigma2 entries and
    // fix `NumberOfSections`.
    zero_section_entry(&mut raw, enigma1_idx)?;
    zero_section_entry(&mut raw, enigma2_idx)?;
    decrement_section_count(&mut raw)?;

    std::fs::write(output, &raw)?;
    Ok(())
}

/// Locate the file offset of the PE Optional Header's data directory array and
/// patch entry `index` to `(rva, size)`.
fn patch_data_directory(
    raw: &mut [u8],
    is_64bit: bool,
    index: usize,
    rva: u32,
    size: u32,
) -> Result<()> {
    let pe_off = u32::from_le_bytes(raw[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_off + 4;
    let opt_header_start = coff + 20;
    let opt_header_size =
        u16::from_le_bytes(raw[coff + 16..coff + 18].try_into().unwrap()) as usize;

    // Offset within the Optional Header where the data directory array starts.
    let dir_offset = if is_64bit { 112 } else { 96 };
    let entry_off = opt_header_start + dir_offset + index * 8;
    if entry_off + 8 > opt_header_start + opt_header_size || entry_off + 8 > raw.len() {
        return Err(EnigmaError::PeRestore(format!(
            "data directory {index} out of range"
        )));
    }
    raw[entry_off..entry_off + 4].copy_from_slice(&rva.to_le_bytes());
    raw[entry_off + 4..entry_off + 8].copy_from_slice(&size.to_le_bytes());
    Ok(())
}

/// Overwrite a section-table entry with zeros (effectively marking it unused).
fn zero_section_entry(raw: &mut [u8], section_index: usize) -> Result<()> {
    let pe_off = u32::from_le_bytes(raw[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_off + 4;
    let opt_header_size =
        u16::from_le_bytes(raw[coff + 16..coff + 18].try_into().unwrap()) as usize;
    let opt_header_start = coff + 20;
    let sec_off = opt_header_start + opt_header_size + section_index * 40;
    if sec_off + 40 > raw.len() {
        return Err(EnigmaError::PeRestore("section entry out of range".into()));
    }
    for b in &mut raw[sec_off..sec_off + 40] {
        *b = 0;
    }
    Ok(())
}

/// Decrement `IMAGE_FILE_HEADER.NumberOfSections` by 2 (we drop both enigma
/// sections). The count lives at coff + 2.
fn decrement_section_count(raw: &mut [u8]) -> Result<()> {
    let pe_off = u32::from_le_bytes(raw[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_off + 4;
    let n = u16::from_le_bytes(raw[coff + 2..coff + 4].try_into().unwrap());
    if n < 2 {
        return Err(EnigmaError::PeRestore(
            "NumberOfSections already < 2".into(),
        ));
    }
    let new_n = n - 2;
    raw[coff + 2..coff + 4].copy_from_slice(&new_n.to_le_bytes());
    Ok(())
}

/// Scan all sections except the two `.enigma*` ones for the first occurrence of
/// `needle` and return its RVA. Mirrors Python's `search_pattern_in_sections`.
fn find_bytes_rva(
    raw: &[u8],
    sections: &[SecInfo],
    needle: &[u8],
    skip_a: usize,
    skip_b: usize,
) -> Option<u32> {
    if needle.is_empty() {
        return None;
    }
    for (i, s) in sections.iter().enumerate() {
        if i == skip_a || i == skip_b {
            continue;
        }
        let start = s.raw_offset as usize;
        let end = start + s.raw_size as usize;
        if end > raw.len() {
            continue;
        }
        if let Some(off) = raw[start..end]
            .windows(needle.len())
            .position(|w| w == needle)
        {
            let file_off = start + off;
            // Convert file offset → RVA using this section's mapping.
            let rva = s.virtual_address as usize + (file_off - start);
            return Some(rva as u32);
        }
    }
    None
}
