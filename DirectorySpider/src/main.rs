use clap::Parser;
use parselnk::Lnk;
use std::collections::{HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

mod helper;
mod metadata;
mod scanner;

const AFTER_HELP: &str = "\
Flags fall in 3 groups:
  files in output    -d  -L  -i  -e
  content scan       -k  --keyword-exclude  --max-scan-size
  search terms       --keywords  --keyword-regex  --case-sensitive

`-k` takes EXTENSIONS, not keywords. Search terms go in `--keywords`.

Examples:
  jinx.exe -d C:\\Users -i txt,log --keywords password,secret
  jinx.exe -d \\\\fs01\\share -i docx,xlsx -o share.json
  jinx.exe -L roots.txt --keyword-regex \"AKIA[0-9A-Z]{16}\"

Run `--help` for full docs and more examples.
";

const AFTER_LONG_HELP: &str = "\
EXAMPLES

Metadata only:
  jinx.exe -d C:\\Users\\Public
  jinx.exe -d C:\\Users -d D:\\Data -o out.json
  jinx.exe -L roots.txt -i exe,dll -e iso

Literal keyword scan (search terms = --keywords, scope = -k/-i):
  jinx.exe -d C:\\Logs -i txt,log --keywords password,secret,api_key
  jinx.exe -d C:\\src --keywords TODO,FIXME --case-sensitive

Regex scan:
  jinx.exe -d C:\\Users -i txt,csv,log \\
      --keyword-regex \"[\\w.+-]+@[\\w.-]+\" \\
      --keyword-regex \"\\d{1,3}(\\.\\d{1,3}){3}\"

Combine + exclude binaries from scan, cap size at 1 MiB:
  jinx.exe -d C:\\Projects -i txt,md,rs,log \\
      --keyword-exclude exe,dll \\
      --keywords password,token \\
      --keyword-regex \"AKIA[0-9A-Z]{16}\" \\
      --max-scan-size 1048576

SMB shares (PowerShell, UNC unquoted unless path has spaces):
  PS> .\\jinx.exe -d \\\\fs01\\share -o share.json
  PS> .\\jinx.exe -d '\\\\fs01\\HR Files' -i docx,xlsx -o hr.json
  PS> .\\jinx.exe `
          -d \\\\dc01\\NETLOGON `
          -d \\\\fs01\\IT\\scripts `
          -i ps1,bat,ini,xml `
          --keywords password,Passw0rd `
          -o creds.json

Follow .lnk shortcuts (may jump to SMB / off-tree targets):
  jinx.exe -d C:\\Users\\Public\\Desktop -f
";

const KEYWORD_REGEX_LONG: &str = "\
Regex pattern to search for in file contents. Repeat flag for multiple patterns.

Rust `regex` crate syntax (PCRE-like, no lookaround/backrefs).
Case-insensitive by default; --case-sensitive overrides.
One pattern per flag (no comma splitting), so quantifiers like `{1,3}` work.

Examples:
  --keyword-regex \"v\\d+\\.\\d+\"               version strings
  --keyword-regex \"[\\w.+-]+@[\\w.-]+\"         email addresses
  --keyword-regex \"\\d{1,3}(\\.\\d{1,3}){3}\"   IPv4 addresses
  --keyword-regex \"TODO|FIXME|HACK\"            any of three tokens
";

/// Recursively collect file metadata and optionally scan contents for keywords/regex.
#[derive(Parser)]
#[command(
    name = "DirectorySpider",
    after_help = AFTER_HELP,
    after_long_help = AFTER_LONG_HELP,
)]
pub struct Args {
    /// Root directory. Repeat `-d` for multiple roots.
    #[arg(short, long)]
    directory_path: Vec<PathBuf>,

    /// File of newline-separated roots (# and blank lines ignored).
    #[arg(short = 'L', long)]
    input_list: Option<PathBuf>,

    /// Output JSON file.
    #[arg(short, long, default_value = "metadata.json")]
    output_path: PathBuf,

    /// Include only these extensions (comma-separated).
    #[arg(short, long, value_delimiter = ',')]
    include: Vec<String>,

    /// Exclude these extensions (comma-separated).
    #[arg(short, long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Follow .lnk shortcuts to their targets.
    #[arg(short, long)]
    follow_lnk: bool,

    /// Extensions to scan for keywords (subset of -i). Takes EXTENSIONS, not search terms.
    #[arg(
        short = 'k',
        long,
        value_delimiter = ',',
        long_help = "Extensions eligible for content scan, comma-separated.\n\
                     Must be a subset of --include. Empty = scan all in-scope files.\n\
                     Takes EXTENSIONS, not keywords. Search terms go in --keywords.\n\
                     Example: -i txt,log -k txt --keywords password"
    )]
    pub keyword_include: Vec<String>,

    /// Extensions never scanned (wins over -k).
    #[arg(long, value_delimiter = ',')]
    pub keyword_exclude: Vec<String>,

    /// Literal search terms (comma-separated). THIS is the keyword flag.
    #[arg(long, value_delimiter = ',')]
    pub keywords: Vec<String>,

    /// Regex pattern to search for. Repeat flag for multiple patterns.
    #[arg(long, long_help = KEYWORD_REGEX_LONG)]
    pub keyword_regex: Vec<String>,

    /// Case-sensitive keyword/regex matching.
    #[arg(long)]
    pub case_sensitive: bool,

    /// Max file size (bytes) scanned for keywords.
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    pub max_scan_size: u64,

    /// Flush output to disk every N entries (0 = only at end).
    #[arg(long, default_value_t = 100)]
    pub flush_every: u64,
}

fn walk_path(
    cli_args: &Args,
    roots: &[PathBuf],
    scanner: &scanner::KeywordScanner,
) -> (u64, std::io::Result<()>) {
    // Validate roots before touching the output file. Skipping every root would otherwise
    // truncate any existing output to `[]` and exit 0 — a silent overwrite on typos.
    let mut valid_roots: Vec<PathBuf> = Vec::with_capacity(roots.len());
    for root in roots {
        if !root.exists() {
            eprintln!("[!] Skipping missing path: {}", root.display());
            continue;
        }
        valid_roots.push(root.clone());
    }
    if valid_roots.is_empty() {
        eprintln!("[!] No valid paths to scan. Output file left untouched.");
        return (0, Ok(()));
    }

    // Create new file | If it fails panic, since continuing doesn't make sense
    let file = File::create(&cli_args.output_path).expect("Unable to open file");

    // Buffered writer for throughput. Flushed periodically below so the file grows
    // on disk during the scan instead of appearing empty until the very end.
    let mut writer = BufWriter::new(file);

    // Open the JSON array manually so we can stream entries one-by-one via
    // serde_json::to_writer and flush at our own cadence.
    writer.write_all(b"[").expect("Unable to write to output file");

    // Init file counter
    let mut file_count: u64 = 0;
    let mut first_entry = true;

    // Periodic flush cadence — push buffered bytes to disk every N entries so the
    // output file grows during the scan instead of appearing empty until the end.
    let flush_every = cli_args.flush_every;

    // Initialize queue and visited set
    let mut queue: VecDeque<PathBuf> = VecDeque::new();
    let mut visited_base_paths: HashSet<PathBuf> = HashSet::new();

    for root in valid_roots {
        queue.push_back(root);
    }

    // Walk path with walkdir and filter out directories
    while let Some(current_base) = queue.pop_front() {
        for entry in WalkDir::new(&current_base)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    // Check if the directory was a base path which we previously visited | If so skip it
                    // This will skip the entire directory
                    let path = e.path();

                    if visited_base_paths.contains(path) {
                        println!(
                            "[*] Skipping directory, since already visited: {}",
                            path.display()
                        );
                    }

                    !visited_base_paths.contains(path)
                } else {
                    // Return true on file
                    true
                }
                // If a file was found just return true
            })
            .filter_map(|e| e.ok()) // Ignore any errors while reading entries
            .filter(|e| e.file_type().is_file()) // Keep only files
            .filter_map(|entry| {
                let path = entry.path();
                let extension = path.extension().and_then(|ext| ext.to_str());

                // Determine if we should include or exclude the entry
                let should_include = cli_args.include.is_empty()
                    || (extension.map_or(false, |ext| cli_args.include.contains(&ext.to_string())));

                let should_exclude =
                    extension.map_or(false, |ext| cli_args.exclude.contains(&ext.to_string()));

                if should_include && !should_exclude {
                    Some(entry)
                } else {
                    None
                }
            })
        {
            // Create a serialized metadata entry
            let mut serialized_entry = match metadata::FileMetadata::metadata_from_dir_entry(&entry) {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("[!] {}", err);
                    continue;
                }
            };

            // Enrich with keyword scan results when in scope
            if scanner.applies_to(&serialized_entry.extension) {
                serialized_entry.matched_keywords =
                    scanner.scan(&serialized_entry.full_path, serialized_entry.size);
            }

            // Write the entry. Failure on a single entry should not abort the scan.
            if let Err(err) = write_entry(
                &mut writer,
                &serialized_entry,
                &mut first_entry,
                &mut file_count,
                flush_every,
            ) {
                eprintln!("[!] {}", err);
            }

            // Check for .lnk files
            if serialized_entry.extension.eq("lnk") && cli_args.follow_lnk{
                // Clone this since this moves it out of context | We may need to use it later

                if serialized_entry
                    .full_path
                    .clone()
                    .to_string_lossy()
                    .is_empty()
                {
                    eprintln!("The full path is empty.");
                    continue;
                }

                let path = std::path::Path::new(&serialized_entry.full_path);

                let lnk = match Lnk::try_from(path) {
                    Ok(value) => value,
                    Err(err) => {
                        eprintln!("[!] {:?}", err);
                        continue;
                    }
                };

                if let Some(target) = lnk.link_info.local_base_path {
                    // Check if the target is a file or directory
                    let target = Path::new(&target);

                    // Check if the target exists since .lnk files may be outdated
                    if target.exists() {
                        // If the target is a file we need the base path for inclusion determination
                        if target.is_file() {
                            if let Some(parent) = target.parent() {
                                // Check if the target path does not include the base path were we started parsing
                                // If false we can skip the file or folder | If true we should parse it
                                if !roots.iter().any(|b| parent.starts_with(b)) {
                                    // Get metadata | Same procedure as with normal files
                                    let mut serialized_entry =
                                        match metadata::FileMetadata::metadata_from_path(target) {
                                            Ok(value) => value,
                                            Err(err) => {
                                                eprintln!("[!] {}", err);
                                                continue;
                                            }
                                        };

                                    // Enrich with keyword scan results when in scope
                                    if scanner.applies_to(&serialized_entry.extension) {
                                        serialized_entry.matched_keywords = scanner
                                            .scan(&serialized_entry.full_path, serialized_entry.size);
                                    }

                                    if let Err(err) = write_entry(
                                        &mut writer,
                                        &serialized_entry,
                                        &mut first_entry,
                                        &mut file_count,
                                        flush_every,
                                    ) {
                                        eprintln!("[!] {}", err);
                                    }
                                }
                            }
                        } else {
                            if !roots.iter().any(|b| target.starts_with(b)) {
                                // If the .lnk points to a directory we add it to the queue to parse it later
                                println!(
                                    "[*] Got lnk directory: {} -> {}",
                                    entry.path().display(),
                                    target.display()
                                );
                                queue.push_back(target.to_path_buf());
                            }
                        }
                    }
                } else {
                    // Print error and continue
                    // eprintln!(
                    //     "[!] Failed to resolve the target path from the shortcut (Likely no file or dir): {:?}",
                    //     serialized_entry.full_path
                    // );
                }
            }
        }

        // Mark this base path as already visited
        visited_base_paths.insert(current_base.clone());
    }

    // Close the JSON array and force a final flush so the file is complete on disk.
    // Final-write failures are propagated to the caller so it can avoid claiming
    // success when the on-disk file is truncated or invalid.
    let finalize = (|| -> std::io::Result<()> {
        writer.write_all(b"]")?;
        writer.flush()?;
        Ok(())
    })();

    (file_count, finalize)
}

/// Serialize a single entry into the open JSON array. Handles the comma separator
/// for all entries after the first, and triggers a periodic flush so readers tailing
/// the output file see progress during long scans.
fn write_entry(
    writer: &mut BufWriter<File>,
    entry: &metadata::FileMetadata,
    first_entry: &mut bool,
    file_count: &mut u64,
    flush_every: u64,
) -> std::io::Result<()> {
    if !*first_entry {
        writer.write_all(b",")?;
    }
    serde_json::to_writer(&mut *writer, entry)?;
    *first_entry = false;
    *file_count += 1;
    if flush_every > 0 && *file_count % flush_every == 0 {
        writer.flush()?;
    }
    Ok(())
}

/// Merge `-d` entries with `--input-list` file contents.
/// Dedupes exact PathBuf matches while preserving first-seen order.
fn collect_roots(args: &Args) -> Result<Vec<PathBuf>, String> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut roots: Vec<PathBuf> = Vec::new();

    for p in &args.directory_path {
        if seen.insert(p.clone()) {
            roots.push(p.clone());
        }
    }

    if let Some(list_path) = &args.input_list {
        let contents = fs::read_to_string(list_path)
            .map_err(|e| format!("failed to read --input-list {}: {}", list_path.display(), e))?;
        for raw in contents.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let p = PathBuf::from(line);
            if seen.insert(p.clone()) {
                roots.push(p);
            }
        }
    }

    if roots.is_empty() {
        return Err("no paths provided (use -d <PATH> and/or -L <FILE>)".to_string());
    }
    Ok(roots)
}

fn main() {
    let args = Args::parse();

    let roots = match collect_roots(&args) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("[!] {}", err);
            std::process::exit(2);
        }
    };

    let scanner = match scanner::KeywordScanner::new(&args) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("[!] Invalid regex: {}", err);
            std::process::exit(2);
        }
    };

    let (file_count, finalize_result) = walk_path(&args, &roots, &scanner);

    if let Err(err) = finalize_result {
        eprintln!(
            "[!] Failed to finalize output {:?}: {} ({} entries written before failure)",
            args.output_path, err, file_count
        );
        std::process::exit(3);
    }

    if file_count > 0 {
        println!(
            "[+] Metadata of {} files has been saved to {:?}",
            file_count, args.output_path
        );
    } else {
        std::process::exit(1);
    }
}
