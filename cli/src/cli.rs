//! Command-line interface for evbunpack-rs.
//!
//! Mirrors the `evbunpack` Python CLI flags (`__main__.py`).

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

/// PE header variant choices, matching `EVB_ENIGMA1_HEADER.{x86,x64}` keys.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum PeVariant {
    /// Enigma Virtual Box 10.x (build >= 70)
    #[value(name = "10_70")]
    V10_70,
    /// Enigma Virtual Box 9.x (build 70)
    #[value(name = "9_70")]
    V9_70,
    /// Enigma Virtual Box 7.x (build 80)
    #[value(name = "7_80")]
    V7_80,
}

impl Default for PeVariant {
    /// Match the Python `__main__()` argument parser default (`9_70`), NOT
    /// the `main()` function's own default of `10_70`.
    fn default() -> Self {
        PeVariant::V9_70
    }
}

impl PeVariant {
    pub fn as_key(self) -> &'static str {
        match self {
            PeVariant::V10_70 => "10_70",
            PeVariant::V9_70 => "9_70",
            PeVariant::V7_80 => "7_80",
        }
    }
}

/// Log level choices matching the Python `--log-level` argument.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Default)]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
    Critical,
}

impl LogLevel {
    pub fn as_filter(self) -> EnvFilter {
        EnvFilter::from_default_env().add_directive(self.as_level().into())
    }

    pub fn as_level(self) -> tracing::Level {
        match self {
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warning => tracing::Level::WARN,
            LogLevel::Error | LogLevel::Critical => tracing::Level::ERROR,
        }
    }
}

/// Enigma Virtual Box Unpacker (Rust port of evbunpack).
#[derive(Debug, Parser)]
#[command(
    name = "evbunpack-rs",
    version,
    about = "Enigma Virtual Box Unpacker",
    long_about = None
)]
pub struct Cli {
    /// Packed EXE to unpack.
    pub input: PathBuf,

    /// Output folder for extracted files.
    pub output: PathBuf,

    /// Don't extract the files; print the table of contents to stderr only.
    #[arg(short = 'l', long = "list", default_value_t = false)]
    pub list: bool,

    /// Don't extract the virtual filesystem.
    #[arg(long = "ignore-fs", default_value_t = false)]
    pub ignore_fs: bool,

    /// Don't restore the executable.
    #[arg(long = "ignore-pe", default_value_t = false)]
    pub ignore_pe: bool,

    /// Use legacy mode for filesystem extraction.
    #[arg(long = "legacy-fs", default_value_t = false)]
    pub legacy_fs: bool,

    /// Unpacker variant to use when unpacking EXEs.
    #[arg(short = 'e', long = "pe-variant", value_enum, default_value_t = PeVariant::V9_70)]
    pub pe_variant: PeVariant,

    /// Where the unpacked EXE is saved. Leave empty to save it in the output folder.
    #[arg(long = "out-pe")]
    pub out_pe: Option<PathBuf>,

    /// Set log level.
    #[arg(long = "log-level", value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,
}

/// Entry point invoked by `main`. Returns the process exit code.
pub fn run(cli: Cli) -> i32 {
    let filter = cli.log_level.as_filter();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    let _guard = tracing::subscriber::set_default(subscriber.finish());

    tracing::info!("Enigma Virtual Box Unpacker v{}", env!("CARGO_PKG_VERSION"));
    tracing::debug!("File: {}", cli.input.display());

    if cli.legacy_fs {
        tracing::warn!("Legacy mode for filesystem extraction enabled");
    }
    if cli.list {
        tracing::warn!("Listing virtual filesystem only");
    }

    if let Err(e) = std::fs::create_dir_all(&cli.output) {
        tracing::error!("Failed to create output directory: {e}");
        return 1;
    }

    let mut exit_code = 0;

    // ---- VFS extraction ----
    if cli.ignore_fs {
        tracing::warn!("Skipping virtual FS extraction");
    } else {
        tracing::info!("Extracting virtual filesystem");
        match evbunpack_rs::extract::extract(
            &cli.input,
            &evbunpack_rs::extract::ExtractOptions {
                out_dir: cli.output.clone(),
                list_only: cli.list,
                legacy_fs: cli.legacy_fs,
            },
        ) {
            Ok(n) => tracing::info!("Extracted {n} VFS entries"),
            Err(evbunpack_rs::error::EnigmaError::InvalidNodeName(name)) => {
                tracing::error!("Invalid node name during VFS walk: {name}");
            }
            Err(e) => {
                tracing::error!("While extracting VFS: {e}");
            }
        }
    }

    // ---- PE restoration ----
    if cli.ignore_pe {
        tracing::warn!("Skipping executable restoration");
    } else {
        tracing::info!("Restoring executable");
        let out_pe = cli.out_pe.clone().unwrap_or_else(|| {
            let mut p = cli.output.clone();
            p.push(cli.input.file_name().unwrap_or_default());
            tracing::info!("Using default executable save path: {}", p.display());
            p
        });

        match evbunpack_rs::pe_restore::restore_pe(&cli.input, &out_pe, cli.pe_variant.as_key()) {
            Ok(()) => tracing::info!("Unpacked PE saved: {}", out_pe.display()),
            Err(e) => {
                tracing::error!("While restoring executable: {e}");
                exit_code = 2;
            }
        }
    }

    exit_code
}
