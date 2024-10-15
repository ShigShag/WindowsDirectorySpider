# Directory Spider Rust

## Prerequisites

Install Rust for [Windows](https://www.rust-lang.org/learn/get-started)

## Run

```powershell
// Compile
PS > cargo build --release

// Binary will be stored in ./target/release/DirectorySpider.exe
PS > ./target/release/DirectorySpider.exe --help
Command line argument parser

Usage: Win64_DirectorySpider.exe [OPTIONS] --directory-path <DIRECTORY_PATH>

Options:
  -d, --directory-path <DIRECTORY_PATH>
          The base directory to start parsing recursively
  -o, --output-path <OUTPUT_PATH>
          Output JSON file (default: metadata.json) [default: metadata.json]
  -i, --include <INCLUDE>
          Include these file extensions, comma-separated (e.g., "exe,txt")
  -e, --exclude <EXCLUDE>
          Exclude these file extensions, comma-separated (e.g., "iso")
  -f, --follow-lnk
          Follow .lnk files (default: false)
  -h, --help
          Print help

## Remarks

* By default this compiles static
* Do not include dots in extensions
