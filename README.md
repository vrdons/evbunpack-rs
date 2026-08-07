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

### Cli Example

```bash
evbunpack x64_PackerTestApp_packed_20240522.exe output
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
