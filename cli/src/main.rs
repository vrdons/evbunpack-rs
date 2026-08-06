mod cli;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    std::process::exit(cli::run(cli));
}
