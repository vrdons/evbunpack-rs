//! Integration tests mirroring `evbunpack/test_unpack_pe.py`.
//!
//! The Python tests unpack each packed corpus PE and *execute* the result.
//! We cannot execute Windows PEs on Linux, so we verify the equivalent
//! invariants instead:
//!
//! 1. VFS extraction produces the expected `README.txt` content byte-for-byte.
//! 2. The restored PE still starts with `MZ` + `PE\0\0` and the section table
//!    no longer contains `.enigma1` / `.enigma2`.

use std::fs;
use std::path::{Path, PathBuf};

use evbunpack_rs::enigma;
use evbunpack_rs::pe_restore::restore_pe;

/// Expected content of the packed VFS (matches Python reference `README.txt`).
const EXPECTED_README: &[u8] = b"Reading from EVB!";

struct CorpusEntry {
    file: &'static str,
    variant: &'static str,
}

const CORPUS: &[CorpusEntry] = &[
    // x64
    CorpusEntry {
        file: "x64_PackerTestApp_packed_20240826.exe",
        variant: "10_70",
    },
    CorpusEntry {
        file: "x64_PackerTestApp_packed_20240613.exe",
        variant: "10_70",
    },
    CorpusEntry {
        file: "x64_PackerTestApp_packed_20240522.exe",
        variant: "10_70",
    },
    CorpusEntry {
        file: "x64_PackerTestApp_packed_20210329.exe",
        variant: "9_70",
    },
    // x86
    CorpusEntry {
        file: "x86_PackerTestApp_packed_20240826.exe",
        variant: "10_70",
    },
    CorpusEntry {
        file: "x86_PackerTestApp_packed_20240613.exe",
        variant: "10_70",
    },
    CorpusEntry {
        file: "x86_PackerTestApp_packed_20240522.exe",
        variant: "10_70",
    },
    CorpusEntry {
        file: "x86_PackerTestApp_packed_20210329.exe",
        variant: "9_70",
    },
    // NOTE: the 7_80 (20170713) corpus files require the legacy VFS layout,
    // which is not yet implemented in Rust (see extract.rs) — the Python
    // reference uses `--legacy-fs` for them.
];

/// Absolute path to the packed corpus file. Cargo runs tests with CWD set to
/// the package root, so `tests/` is relative to that.
fn corpus_path(name: &str) -> PathBuf {
    let p = Path::new("tests").join(name);
    assert!(p.exists(), "missing corpus file: {}", p.display());
    p
}

/// Restore the PE in-memory by calling the library and reading the output.
fn restore_to_bytes(input: &Path, variant: &str, out: &Path) -> Vec<u8> {
    restore_pe(input, out, variant).expect("restore_pe succeeds");
    fs::read(out).expect("restored PE is readable")
}

fn assert_is_valid_pe(data: &[u8]) {
    assert_eq!(&data[..2], b"MZ", "missing MZ magic");
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(&data[pe_off..pe_off + 4], b"PE\0\0", "missing PE signature");
}

/// Assert the section table contains no `.enigma1` / `.enigma2` sections.
fn assert_no_enigma_sections(data: &[u8]) {
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_off + 4;
    let num_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().unwrap());
    let opt_size = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().unwrap());
    let section_table = coff + 20 + opt_size as usize;

    for i in 0..num_sections as usize {
        let entry = section_table + i * 40;
        let name = &data[entry..entry + 8];
        let name = std::str::from_utf8(name)
            .unwrap_or("")
            .trim_end_matches('\0');
        assert!(
            !name.starts_with(".enigma"),
            "section table still contains {name:?}"
        );
    }
}

/// Full round-trip: unpack VFS + restore PE into a temp dir.
fn roundtrip(entry: &CorpusEntry, tmp: &Path) {
    let input = corpus_path(entry.file);

    // --- VFS extraction ---
    let files = enigma::unpack(&input).expect("VFS unpack succeeds");
    let readme = files
        .iter()
        .find(|f| f.path.ends_with("README.txt"))
        .expect("README.txt is present in VFS");
    assert_eq!(readme.data, EXPECTED_README, "README.txt content mismatch");

    // --- PE restoration ---
    let out_pe = tmp.join(entry.file);
    let restored = restore_to_bytes(&input, entry.variant, &out_pe);
    assert_is_valid_pe(&restored);
    assert_no_enigma_sections(&restored);
}

#[test]
fn unpack_all_x64_corpus() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for entry in CORPUS.iter().filter(|e| e.file.starts_with("x64_")) {
        roundtrip(entry, tmp.path());
    }
}

#[test]
fn unpack_all_x86_corpus() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for entry in CORPUS.iter().filter(|e| e.file.starts_with("x86_")) {
        roundtrip(entry, tmp.path());
    }
}
