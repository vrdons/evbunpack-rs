# evbunpack-rs

Rust implementation of [Enigma Virtual Box](https://enigmaprotector.com/en/downloads/changelogenigmavb.html) unpacker — a port of the [evbunpack](https://github.com/mos9527/evbunpack) Python project.

## Features

- **Executable unpacking**
  - Recovers TLS, Exception, Import and Relocation directories from `.enigma1`
  - Strips the Enigma loader sections (`.enigma1` / `.enigma2`)
  - Preserves PE overlays
- **Virtual filesystem unpacking**
  - Extracts built-in files and external packages
  - Supports compressed (aPLib) mode

## Workspace layout

```
Cargo.toml          library crate: evbunpack_rs (no CLI dependencies)
cli/                binary crate: evbunpack-rs (clap, tracing-subscriber)
src/
  enigma.rs         PE parser, VFS records walker, aPLib decompressor
  pe_restore.rs     original PE restoration from .enigma1
  extract.rs        high-level VFS extraction driver
  error.rs          typed error enums
```

The workspace split keeps CLI-only dependencies (`clap`, `tracing-subscriber`) out of the library's dependency graph — dependents of `evbunpack_rs` only pull `goblin`, `thiserror`, and `tracing`.


## Usage

```
Usage: evbunpack-rs [OPTIONS] <INPUT> <OUTPUT>

Arguments:
  <INPUT>   Packed EXE to unpack
  <OUTPUT>  Output folder for extracted files

Options:
  -l, --list                      Don't extract the files; print the table of contents to stderr only
      --ignore-fs                 Don't extract the virtual filesystem
      --ignore-pe                 Don't restore the executable
      --legacy-fs                 Use legacy mode for filesystem extraction
  -e, --pe-variant <PE_VARIANT>   Unpacker variant [default: 9_70] [possible values: 10_70, 9_70, 7_80]
      --out-pe <OUT_PE>           Where the unpacked EXE is saved. Leave empty to save it in the output folder
      --log-level <LOG_LEVEL>     Set log level [default: info] [possible values: debug, info, warning, error, critical]
  -h, --help                      Print help
  -V, --version                   Print version
```

### Example

```bash
evbunpack-rs x64_PackerTestApp_packed_20240522.exe output
```

Extracts `output/README.txt` and writes the restored executable to `output/x64_PackerTestApp_packed_20240522.exe`.

## Tested versions

The PE unpacking variant must match the packer version — try the other variants with `-e` if one doesn't work.

| Packer version | Unpack with flags |
| - | - |
| 11.00 | `-e 10_70` |
| 10.70 | `-e 10_70` |
| 9.70 | `-e 9_70` |
| 7.80 | `-e 7_80 --legacy-fs` |

## Testing

```bash
cargo test --workspace
```

The corpus lives in `tests/` (packed PackerTestApp binaries for x86/x64 across EVB 7.80/9.70/10.70).