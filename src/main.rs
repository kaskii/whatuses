use clap::Parser;
use std::path::PathBuf;

mod checks;

use checks::file::check_file;
use checks::port::check_port;

/// A command-line utility to identify processes using a file or listening on a network port.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File path or network port to investigate
    #[arg(value_name = "INPUT")]
    input: Option<String>,

    /// Specific network port to check
    #[arg(short, long, value_name = "PORT")]
    port: Option<u16>,

    /// Enable detailed output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    if args.verbose {
        println!("Verbose logging enabled.");
    }

    if let Some(port) = args.port {
        check_port(port, args.verbose);
    } else if let Some(input) = args.input {
        // Try to parse input as a port first
        if let Ok(port) = input.parse::<u16>() {
            check_port(port, args.verbose);
        } else {
            // Otherwise, treat it as a file path
            check_file(PathBuf::from(input), args.verbose);
        }
    } else {
        println!("Error: No input provided. Run with --help for usage details.");
    }
}
