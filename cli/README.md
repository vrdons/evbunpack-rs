# evbunpack-cli

## Features

- **Executable unpacking**
  - Recovers TLS, Exception, Import and Relocation directories from `.enigma1`
  - Strips the Enigma loader sections (`.enigma1` / `.enigma2`)
  - Preserves PE overlays
- **Virtual filesystem unpacking**
  - Extracts built-in files and external packages
  - Supports compressed (aPLib) mode


## Usage

```
Usage: evbunpack [OPTIONS] <INPUT> <OUTPUT>

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
