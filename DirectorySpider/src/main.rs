use clap::Parser;
use parselnk::Lnk;
use std::collections::{HashSet, VecDeque};
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use struson::writer::{JsonStreamWriter, JsonWriter};
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
}

fn walk_path(cli_args: &Args, roots: &[PathBuf], scanner: &scanner::KeywordScanner) -> u64 {
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
        return 0;
    }

    // Create new file | If it fails panic, since continuing doesn't make sense
    let file = File::create(&cli_args.output_path).expect("Unable to open file");

    // Create a new writer for the file
    let mut writer = BufWriter::new(file);

    // Pass the write to the json parser
    let mut json_writer = JsonStreamWriter::new(&mut writer);

    // Begin an array | Same as above, panic if this fails since continuing doesn't make sense
    json_writer.begin_array().unwrap();

    // Init file counter
    let mut file_count: u64 = 0;

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

            // Match the response, failure should not affect other entries, therefore no panic
            match json_writer.serialize_value(&serialized_entry) {
                Ok(_) => {
                    // If ok count up
                    file_count += 1
                }
                Err(err) => {
                    eprintln!("[!] {}", err);
                }
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

                                    // Match the response, failure should not affect other entries, therefore no panic
                                    match json_writer.serialize_value(&serialized_entry) {
                                        Ok(_) => {
                                            // If ok count up
                                            // println!(
                                            //     "[*] Got lnk file: {} -> {}",
                                            //     entry.path().display(),
                                            //     target.display()
                                            // );

                                            file_count += 1
                                        }
                                        Err(err) => {
                                            eprintln!("[!] {}", err);
                                        }
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

    // Also escape this error to try and finish the document
    if let Err(err) = json_writer.end_array() {
        eprintln!("[!] Error ending JSON array: {}", err);
    }

    // If this fails :(
    json_writer.finish_document().unwrap();

    // Return file count
    file_count
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

    let file_count = walk_path(&args, &roots, &scanner);

    if file_count > 0 {
        println!(
            "[+] Metadata of {} files has been saved to {:?}",
            file_count, args.output_path
        );
    } else {
        std::process::exit(1);
    }
}
