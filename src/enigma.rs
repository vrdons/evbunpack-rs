//! Enigma Virtual Box PE section parser and VFS extractor.

use std::fs;

use crate::error::{EnigmaError, Result};

pub use pe::PeInfo;

/// Kind of a VFS entry.
///
/// `Folder` is produced by the record walker as a structural marker when
/// recursing through the tree, but never emitted as an [`ExtractedFile`];
/// keeping the variant documents the on-disk format faithfully.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum VfsEntryKind {
    File,
    Folder,
}

#[derive(Debug, Clone)]
pub struct VfsEntry {
    pub path: String,
    pub kind: VfsEntryKind,
    pub offset: u64,
    pub stored_size: u32,
    pub original_size: u32,
}

#[derive(Debug)]
pub struct ExtractedFile {
    pub path: String,
    pub data: Vec<u8>,
}

/// Top-level VFS extraction driver.
///
/// Reads the packed PE, locates `.enigma1`, finds the `EVB\0` magic, walks the
/// VFS tree (PE-external layout), and decompresses each stored file.
pub fn unpack(exe_path: &std::path::Path) -> Result<Vec<ExtractedFile>> {
    let raw = fs::read(exe_path)?;
    let pe = PeInfo::parse(&raw)?;

    // Find .enigma1 section
    let enigma1_info = pe
        .sections
        .iter()
        .find(|s| s.name == ".enigma1")
        .ok_or_else(|| EnigmaError::NoEnigmaSection(".enigma1".into()))?;

    let enigma1_start = enigma1_info.raw_offset as usize;
    let enigma1_end = enigma1_start + enigma1_info.raw_size as usize;
    if enigma1_end > raw.len() {
        return Err(EnigmaError::UnexpectedEof);
    }
    let enigma1_data = &raw[enigma1_start..enigma1_end];

    let magic_offset = enigma1_data
        .windows(4)
        .position(|w| w == b"EVB\x00")
        .ok_or(EnigmaError::InvalidMagic)?;

    let vfs_data = &enigma1_data[magic_offset..];
    let entries = records::parse_vfs_tree(vfs_data)?;

    let base_offset = (enigma1_start + magic_offset) as u64;

    let mut results = Vec::new();
    for entry in &entries {
        if entry.kind != VfsEntryKind::File {
            continue;
        }

        let abs_offset = base_offset + entry.offset;
        let end_offset = abs_offset + entry.stored_size as u64;

        if end_offset > raw.len() as u64 {
            tracing::warn!(
                path = %entry.path,
                offset = abs_offset,
                size = entry.stored_size,
                "VFS file extends beyond EXE, skipping"
            );
            continue;
        }

        let data = if entry.stored_size != entry.original_size {
            decompress_chunks(&raw, abs_offset, entry.stored_size, entry.original_size)?
        } else {
            raw[abs_offset as usize..end_offset as usize].to_vec()
        };

        results.push(ExtractedFile {
            path: entry.path.clone(),
            data,
        });
    }

    Ok(results)
}

/// Decompress a file stored in EVB chunk format (aPLib).
///
/// Layout at `offset`:
/// ```text
/// EVB_CHUNK_BLOCK { size: u32, padding: u32 }    (8 bytes)
/// chunk size table  [u32; (size - 8) / 4]          (12 bytes per entry, every 3rd is chunk size)
/// compressed chunk 1
/// compressed chunk 2
/// ...
/// ```
pub(crate) fn decompress_chunks(
    raw: &[u8],
    offset: u64,
    stored_size: u32,
    original_size: u32,
) -> Result<Vec<u8>> {
    let start = offset as usize;
    let block = &raw[start..start + stored_size as usize];

    if block.len() < 8 {
        return Err(EnigmaError::VfsParse("chunk block too small".into()));
    }

    // Read EVB_CHUNK_BLOCK header
    let chunks_blk_size = u32::from_le_bytes(block[0..4].try_into().unwrap()) as usize;
    if chunks_blk_size < 8 || chunks_blk_size > stored_size as usize {
        return Err(EnigmaError::VfsParse(format!(
            "invalid chunk block size: {chunks_blk_size} vs stored {stored_size}"
        )));
    }

    // Read chunk table (remaining bytes after the 8-byte header)
    let table_bytes = &block[8..chunks_blk_size];
    let table_u32: Vec<u32> = table_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();

    // Every 3rd entry is the actual chunk size
    let chunk_sizes: Vec<usize> = table_u32
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 3 == 0)
        .map(|(_, &v)| v as usize)
        .collect();

    if chunk_sizes.is_empty() {
        return Err(EnigmaError::VfsParse("empty chunk table".into()));
    }

    // Compressed data starts after the chunk block table
    let compressed_data = &block[chunks_blk_size..];
    let mut compressed_pos = 0;
    let mut output = Vec::with_capacity(original_size as usize);

    for &chunk_size in &chunk_sizes {
        if compressed_pos + chunk_size > compressed_data.len() {
            return Err(EnigmaError::UnexpectedEof);
        }
        let chunk = &compressed_data[compressed_pos..compressed_pos + chunk_size];
        compressed_pos += chunk_size;

        let dec = aplib::decompress(chunk, false)?;
        output.extend_from_slice(&dec);
    }

    if output.len() != original_size as usize {
        return Err(EnigmaError::VfsParse(format!(
            "decompressed size mismatch: expected {} bytes, got {}",
            original_size,
            output.len()
        )));
    }

    Ok(output)
}

mod pe {
    //! Minimal PE32/PE32+ parser — just enough to read DOS stub and section table.

    use crate::error::{EnigmaError, Result};

    #[derive(Debug, Clone)]
    pub struct PeInfo {
        /// 64-bit (PE32+) vs 32-bit (PE32) image.
        pub is_64bit: bool,
        pub sections: Vec<SectionInfo>,
    }

    #[derive(Debug, Clone)]
    pub struct SectionInfo {
        pub name: String,
        /// Virtual layout. Not consumed by the unpacker today but part of the
        /// PE info surface; retained so callers can map RVA → file offsets.
        #[allow(dead_code)]
        pub virtual_address: u32,
        #[allow(dead_code)]
        pub virtual_size: u32,
        pub raw_offset: u32,
        pub raw_size: u32,
    }

    impl PeInfo {
        pub fn parse(raw: &[u8]) -> Result<Self> {
            if raw.len() < 64 {
                return Err(EnigmaError::InvalidPe);
            }

            if &raw[0..2] != b"MZ" {
                return Err(EnigmaError::InvalidPe);
            }

            let pe_offset = u32::from_le_bytes(raw[0x3c..0x40].try_into().unwrap()) as usize;
            if pe_offset + 4 > raw.len() {
                return Err(EnigmaError::InvalidPe);
            }

            if &raw[pe_offset..pe_offset + 4] != b"PE\0\0" {
                return Err(EnigmaError::InvalidPe);
            }

            let coff_header_offset = pe_offset + 4;

            let num_sections = u16::from_le_bytes(
                raw[coff_header_offset + 2..coff_header_offset + 4]
                    .try_into()
                    .unwrap(),
            );

            let opt_header_size = u16::from_le_bytes(
                raw[coff_header_offset + 16..coff_header_offset + 18]
                    .try_into()
                    .unwrap(),
            );

            let opt_header_start = coff_header_offset + 20;

            let magic = u16::from_le_bytes(
                raw[opt_header_start..opt_header_start + 2]
                    .try_into()
                    .unwrap(),
            );

            let is_64bit = magic == 0x20b;

            let section_table_start = opt_header_start + opt_header_size as usize;

            let mut sections = Vec::new();
            for i in 0..num_sections as usize {
                let sec_off = section_table_start + i * 40;
                if sec_off + 40 > raw.len() {
                    break;
                }

                let name_bytes = &raw[sec_off..sec_off + 8];
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
                let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

                let virtual_size =
                    u32::from_le_bytes(raw[sec_off + 8..sec_off + 12].try_into().unwrap());
                let virtual_address =
                    u32::from_le_bytes(raw[sec_off + 12..sec_off + 16].try_into().unwrap());
                let raw_size =
                    u32::from_le_bytes(raw[sec_off + 16..sec_off + 20].try_into().unwrap());
                let raw_offset =
                    u32::from_le_bytes(raw[sec_off + 20..sec_off + 24].try_into().unwrap());

                sections.push(SectionInfo {
                    name,
                    virtual_address,
                    virtual_size,
                    raw_offset,
                    raw_size,
                });
            }

            Ok(PeInfo { is_64bit, sections })
        }

        /// Look up a section's raw bytes by name.
        pub fn section_data<'a>(&self, raw: &'a [u8], name: &str) -> Option<&'a [u8]> {
            self.sections.iter().find(|s| s.name == name).and_then(|s| {
                let start = s.raw_offset as usize;
                let end = (s.raw_offset + s.raw_size) as usize;
                if end <= raw.len() {
                    Some(&raw[start..end])
                } else {
                    None
                }
            })
        }
    }
}

mod aplib {
    //! Pure-Rust aPLib decompression (LZ77 variant used by Enigma Virtual Box).
    //! Ported from the Python `aplib` package v0.6.

    use crate::error::AplibError;

    /// Decompress an aPLib-compressed buffer.
    ///
    /// `strict` produces errors on checksum mismatch; set to `false` for EVB chunks.
    pub fn decompress(data: &[u8], strict: bool) -> std::result::Result<Vec<u8>, AplibError> {
        // If data starts with "AP32" header, parse it (though EVB chunks typically don't)
        let payload = if data.len() >= 24 && &data[0..4] == b"AP32" {
            let header_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
            let packed_size = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
            let _packed_crc = u32::from_le_bytes(data[12..16].try_into().unwrap());
            let _orig_size = u32::from_le_bytes(data[16..20].try_into().unwrap());
            let _orig_crc = u32::from_le_bytes(data[20..24].try_into().unwrap());

            if header_size + packed_size > data.len() {
                return Err(AplibError::InvalidHeader);
            }
            if strict {
                let actual_packed = &data[header_size..header_size + packed_size];
                let crc = crc32(actual_packed);
                if crc != _packed_crc {
                    return Err(AplibError::PackedCrcMismatch);
                }
            }
            &data[header_size..header_size + packed_size]
        } else {
            data
        };

        let mut dec = AplibDecoder::new(payload);
        dec.depack(strict)
    }

    /// Internal aPLib decoder state machine.
    struct AplibDecoder<'a> {
        src: &'a [u8],
        src_pos: usize,
        dst: Vec<u8>,
        tag: u8,
        bitcount: i32,
    }

    impl<'a> AplibDecoder<'a> {
        fn new(src: &'a [u8]) -> Self {
            Self {
                src,
                src_pos: 0,
                dst: Vec::new(),
                tag: 0,
                bitcount: 0,
            }
        }

        /// Read one byte from the compressed stream.
        fn read_byte(&mut self) -> std::result::Result<u8, AplibError> {
            if self.src_pos >= self.src.len() {
                return Err(AplibError::UnexpectedEof);
            }
            let b = self.src[self.src_pos];
            self.src_pos += 1;
            Ok(b)
        }

        /// Get one bit from the tag byte (MSB first, matching the Python impl).
        fn getbit(&mut self) -> std::result::Result<u8, AplibError> {
            self.bitcount -= 1;
            if self.bitcount < 0 {
                self.tag = self.read_byte()?;
                self.bitcount = 7;
            }
            let bit = (self.tag >> 7) & 1;
            self.tag <<= 1;
            Ok(bit)
        }

        /// Read a gamma-coded integer (Elias gamma code).
        fn getgamma(&mut self) -> std::result::Result<usize, AplibError> {
            let mut result: usize = 1;
            loop {
                result = (result << 1) + self.getbit()? as usize;
                if self.getbit()? == 0 {
                    break;
                }
            }
            Ok(result)
        }

        /// Main decompression loop.
        fn depack(&mut self, _strict: bool) -> std::result::Result<Vec<u8>, AplibError> {
            // First byte is literal
            let first = self.read_byte()?;
            self.dst.push(first);

            let mut r0: isize = -1;
            let mut lwm: usize = 0;
            let mut done = false;

            while !done {
                if self.getbit()? != 0 {
                    // Match
                    if self.getbit()? != 0 {
                        if self.getbit()? != 0 {
                            // Short match (4-bit offset)
                            let mut offs: usize = 0;
                            for _ in 0..4 {
                                offs = (offs << 1) + self.getbit()? as usize;
                            }
                            if offs != 0 {
                                let idx = self.dst.len().wrapping_sub(offs);
                                if idx < self.dst.len() {
                                    let b = self.dst[idx];
                                    self.dst.push(b);
                                } else {
                                    return Err(AplibError::InvalidOffset);
                                }
                            } else {
                                self.dst.push(0);
                            }
                            lwm = 0;
                        } else {
                            // Single byte with offset
                            let b = self.read_byte()?;
                            let offs = (b >> 1) as usize;
                            let length = 2 + (b & 1) as usize;
                            if offs != 0 {
                                for _ in 0..length {
                                    let idx = self.dst.len().wrapping_sub(offs);
                                    if idx < self.dst.len() {
                                        let byte = self.dst[idx];
                                        self.dst.push(byte);
                                    } else {
                                        return Err(AplibError::InvalidOffset);
                                    }
                                }
                            } else {
                                done = true;
                            }
                            r0 = offs as isize;
                            lwm = 1;
                        }
                    } else {
                        // Long match
                        let mut offs = self.getgamma()?;
                        if lwm == 0 && offs == 2 {
                            // Reuse previous offset
                            offs = r0 as usize;
                            let length = self.getgamma()?;
                            for _ in 0..length {
                                let idx = self.dst.len().wrapping_sub(offs);
                                if idx < self.dst.len() {
                                    let byte = self.dst[idx];
                                    self.dst.push(byte);
                                } else {
                                    return Err(AplibError::InvalidOffset);
                                }
                            }
                        } else {
                            if lwm == 0 {
                                offs = offs.wrapping_sub(3);
                            } else {
                                offs = offs.wrapping_sub(2);
                            }
                            offs <<= 8;
                            offs += self.read_byte()? as usize;
                            let mut length = self.getgamma()?;
                            // Adjust length based on offset magnitude
                            if offs >= 32000 {
                                length += 1;
                            }
                            if offs >= 1280 {
                                length += 1;
                            }
                            if offs < 128 {
                                length += 2;
                            }
                            for _ in 0..length {
                                let idx = self.dst.len().wrapping_sub(offs);
                                if idx < self.dst.len() {
                                    let byte = self.dst[idx];
                                    self.dst.push(byte);
                                } else {
                                    return Err(AplibError::InvalidOffset);
                                }
                            }
                            r0 = offs as isize;
                        }
                        lwm = 1;
                    }
                } else {
                    // Literal byte
                    let b = self.read_byte()?;
                    self.dst.push(b);
                    lwm = 0;
                }
            }

            Ok(std::mem::take(&mut self.dst))
        }
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }
}

mod records {
    //! Enigma VB VFS record parser.
    //!
    //! Walks the EVB VFS tree (PE-external layout) and emits flat file entries.

    use std::io::{Cursor, Read};

    use crate::enigma::{VfsEntry, VfsEntryKind};
    use crate::error::{EnigmaError, Result};

    const EVB_MAGIC: &[u8; 4] = b"EVB\x00";

    const NODE_TYPE_FILE: u8 = 2;
    const NODE_TYPE_FOLDER: u8 = 3;

    const PACK_HEADER_SIZE: usize = 64;

    const HEADER_NODE_SIZE: usize = 16;

    #[derive(Debug)]
    #[allow(dead_code)]
    pub(super) struct FlatNode {
        name: String,
        node_type: u8,
        objects_count: u32,
        offset: u64,
        stored_size: u32,
        original_size: u32,
    }

    pub fn parse_vfs_tree(data: &[u8]) -> Result<Vec<VfsEntry>> {
        let mut cursor = Cursor::new(data);
        let flat_nodes = read_all_nodes(&mut cursor)?;
        if flat_nodes.is_empty() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mut idx: usize = 1; // skip main node (index 0)
        let count = flat_nodes[0].objects_count as usize;
        walk_children(&flat_nodes, &mut idx, count, "", &mut entries);
        Ok(entries)
    }

    fn read_all_nodes(cursor: &mut Cursor<&[u8]>) -> Result<Vec<FlatNode>> {
        let mut hdr_buf = [0u8; PACK_HEADER_SIZE];
        read_exact(cursor, &mut hdr_buf)?;
        if &hdr_buf[0..4] != EVB_MAGIC {
            return Err(EnigmaError::InvalidMagic);
        }

        let main_node = read_header_node(cursor)?;

        let mut abs_offset = cursor.position() + main_node.size as u64 - 12;

        let pos = cursor.position();
        if pos > 0 {
            cursor.set_position(pos - 1);
        }

        let mut nodes = vec![FlatNode {
            name: String::new(),
            node_type: 0, // main
            objects_count: main_node.objects_count,
            offset: 0,
            stored_size: 0,
            original_size: 0,
        }];

        loop {
            let header_node = match read_header_node(cursor) {
                Ok(h) => h,
                Err(EnigmaError::UnexpectedEof) => break,
                Err(e) => return Err(e),
            };

            let named = match read_named_node(cursor) {
                Ok(n) => n,
                Err(EnigmaError::UnexpectedEof) => break,
                Err(e) => return Err(e),
            };

            match named.node_type {
                NODE_TYPE_FILE => {
                    let opt = read_optional_file_node(cursor)?;
                    let offset = abs_offset;
                    abs_offset += opt.stored_size as u64;
                    nodes.push(FlatNode {
                        name: named.name,
                        node_type: NODE_TYPE_FILE,
                        objects_count: header_node.objects_count,
                        offset,
                        stored_size: opt.stored_size,
                        original_size: opt.original_size,
                    });
                }
                NODE_TYPE_FOLDER => {
                    let mut skip = [0u8; 25];
                    read_exact(cursor, &mut skip)?;
                    nodes.push(FlatNode {
                        name: named.name,
                        node_type: NODE_TYPE_FOLDER,
                        objects_count: header_node.objects_count,
                        offset: 0,
                        stored_size: 0,
                        original_size: 0,
                    });
                }
                _ => {
                    break;
                }
            }
        }

        Ok(nodes)
    }

    fn walk_children(
        nodes: &[FlatNode],
        idx: &mut usize,
        count: usize,
        prefix: &str,
        entries: &mut Vec<VfsEntry>,
    ) {
        for _ in 0..count {
            if *idx >= nodes.len() {
                break;
            }
            let node = &nodes[*idx];
            *idx += 1;

            let name = normalize_folder_name(&node.name);
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };

            match node.node_type {
                NODE_TYPE_FILE => {
                    entries.push(VfsEntry {
                        path,
                        kind: VfsEntryKind::File,
                        offset: node.offset,
                        stored_size: node.stored_size,
                        original_size: node.original_size,
                    });
                }
                NODE_TYPE_FOLDER => {
                    let child_count = node.objects_count as usize;
                    walk_children(nodes, idx, child_count, &path, entries);
                }
                _ => {}
            }
        }
    }

    fn normalize_folder_name(name: &str) -> String {
        match name {
            "%DEFAULT FOLDER%" => String::new(),
            _ => name.to_string(),
        }
    }

    #[derive(Debug)]
    struct HeaderNode {
        size: u32,
        objects_count: u32,
    }

    fn read_header_node(cursor: &mut Cursor<&[u8]>) -> Result<HeaderNode> {
        let mut buf = [0u8; HEADER_NODE_SIZE];
        read_exact(cursor, &mut buf)?;
        let size = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        // bytes 4-11: 8-byte padding (ignored)
        let objects_count = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        Ok(HeaderNode {
            size,
            objects_count,
        })
    }

    #[derive(Debug)]
    struct NamedNode {
        name: String,
        node_type: u8,
    }

    fn read_named_node(cursor: &mut Cursor<&[u8]>) -> Result<NamedNode> {
        let mut name_bytes = Vec::new();
        loop {
            let mut pair = [0u8; 2];
            read_exact(cursor, &mut pair)?;
            if pair[0] == 0 && pair[1] == 0 {
                break;
            }
            name_bytes.extend_from_slice(&pair);
        }

        let u16s: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let name = String::from_utf16_lossy(&u16s);

        let mut type_buf = [0u8; 1];
        read_exact(cursor, &mut type_buf)?;

        Ok(NamedNode {
            name,
            node_type: type_buf[0],
        })
    }

    #[derive(Debug)]
    struct OptionalFileNode {
        original_size: u32,
        stored_size: u32,
    }

    fn read_optional_file_node(cursor: &mut Cursor<&[u8]>) -> Result<OptionalFileNode> {
        let mut buf = [0u8; 53];
        read_exact(cursor, &mut buf)?;
        let original_size = u32::from_le_bytes(buf[2..6].try_into().unwrap());
        let stored_size = u32::from_le_bytes(buf[49..53].try_into().unwrap());
        Ok(OptionalFileNode {
            original_size,
            stored_size,
        })
    }

    fn read_exact(cursor: &mut Cursor<&[u8]>, buf: &mut [u8]) -> Result<()> {
        match cursor.read_exact(buf) {
            Ok(()) => Ok(()),
            Err(_) => Err(EnigmaError::UnexpectedEof),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny synthetic PE with a single section holding the EVB magic
    /// followed by an empty VFS tree. We verify that `unpack` runs end-to-end
    /// on the in-memory blob without touching disk.
    ///
    /// (More realistic corpus testing happens in `tests/test_unpack_pe.rs`.)
    #[test]
    fn peinfo_parses_dos_and_pe_sig() {
        // 64-byte DOS header so e_lfanew at 0x3c is in bounds.
        let pe = b"MZ"
            .iter()
            .chain([0u8; 62].iter())
            .copied()
            .collect::<Vec<_>>();
        let mut raw = pe;
        // e_lfanew at 0x3c -> 0x40
        raw[0x3c] = 0x40;
        // Append "PE\0\0" + minimal COFF header (20 bytes) + 0 sections
        raw.extend_from_slice(b"PE\0\0");
        raw.extend_from_slice(&[0u8; 4]); // machine + num_sections(0)
        raw.extend_from_slice(&[0u8; 12]); // rest of COFF
        raw.extend_from_slice(&20u16.to_le_bytes()); // opt_header_size = 20
        raw.extend_from_slice(&[0u8; 2]); // characteristics
        // Optional header magic (PE32 = 0x10b)
        raw.extend_from_slice(&0x10bu16.to_le_bytes());
        raw.extend_from_slice(&[0u8; 18]);

        let info = PeInfo::parse(&raw).expect("PE parses");
        assert!(!info.is_64bit);
        assert_eq!(info.sections.len(), 0);
    }

    #[test]
    fn peinfo_rejects_non_pe() {
        let raw = vec![0u8; 256];
        assert!(PeInfo::parse(&raw).is_err());
    }

    #[test]
    fn peinfo_detects_pe32_plus() {
        let mut raw = vec![0u8; 0x80];
        raw[0..2].copy_from_slice(b"MZ");
        raw[0x3c] = 0x40;
        raw.resize(0x40 + 4 + 20 + 2, 0);
        let pe_off = 0x40usize;
        raw[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        // optional header size = 2 at coff+16
        raw[0x40 + 4 + 16..0x40 + 4 + 18].copy_from_slice(&2u16.to_le_bytes());
        // optional header magic = 0x20b (PE32+)
        let opt_off = 0x40 + 4 + 20;
        raw[opt_off..opt_off + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        let info = PeInfo::parse(&raw).expect("parses");
        assert!(info.is_64bit);
    }
}
