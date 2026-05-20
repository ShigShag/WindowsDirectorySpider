use clap::Parser;
use parselnk::Lnk;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use walkdir::WalkDir;

mod context_index;
mod helper;
mod metadata;
mod scanner;

const AFTER_HELP: &str = "\
Note: `-k` takes EXTENSIONS, not keywords. Search terms go in `--keywords`.

Examples:
  jinx.exe -d C:\\Users -i txt,log --keywords password,secret
  jinx.exe -d \\\\fs01\\share -i docx,xlsx -o share.json
  jinx.exe -L roots.txt --keyword-regex \"AKIA[0-9A-Z]{16}\"
  jinx.exe -d C:\\Logs -i txt,log --keywords password --matches-only
  jinx.exe -d C:\\Logs -i txt,log --keywords password --matches-only --hash-context-lines
  jinx.exe -d C:\\Logs -i txt,log --keywords password --matches-only --threads 4

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
  jinx.exe -d C:\\Users -i txt,log --keywords-file wordlist.txt

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

Matches-only mode (emit only files with hits, include snippet around each match):
  jinx.exe -d C:\\Logs -i txt,log --keywords password,secret \\
      --matches-only --context-lines 2 --context-words 6 \\
      --max-context-line-chars 500

Parallel scan, preserving deterministic JSON output order:
  jinx.exe -d C:\\Logs -i txt,log --keywords password,secret \\
      --matches-only --threads 4

Deduplicate large context snippets with a sidecar hash index:
  jinx.exe -d C:\\Logs -i txt,log --keywords password,secret \\
      --matches-only --context-lines 5 --context-words 0 \\
      --hash-context-lines --context-index-path context-index.json

  Each match in `matches[]` is split into `before` / `match` / `after` exact
  substrings of the decoded file content. `line` is 1-based; `column` is the
  1-based BYTE offset of the match start within its line (not character or
  grapheme — multibyte UTF-8 counts each byte). `before` and `after` preserve
  original line endings: CRLF files keep their `\\r` bytes.
  --max-context-line-chars caps each emitted context line/segment while keeping
  text nearest the match (0 = unlimited). The --max-matches-per-file cap
  (default 100) bounds `matches[]` per file; `matched_keywords` still lists
  every distinct needle that matched, independent of the cap.
  --hash-context-lines works with or without --matches-only. It replaces
  `before` / `after` with `before_hash` / `after_hash` keys for emitted
  matches and writes a sidecar index at the end of the scan. The sidecar maps
  compact BLAKE3-128 base64url hashes to the original context text. If
  --context-index-path is omitted, the sidecar path is derived from
  --output-path. Valid zero-match hash-mode scans leave an empty sidecar index.
  Use --live-context-index to rewrite the full sidecar snapshot whenever a new
  context value is indexed, before emitting entries that reference newly indexed
  context. Live mode is useful for crash/tail-reader decodability but is more
  sensitive to Windows/SMB file replacement failures.
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
    // === Files in output ===
    /// Root directory. Repeat `-d` for multiple roots.
    #[arg(short, long, help_heading = "Files in output")]
    directory_path: Vec<PathBuf>,

    /// File of newline-separated roots (# and blank lines ignored).
    #[arg(short = 'L', long, help_heading = "Files in output")]
    input_list: Option<PathBuf>,

    /// Include only these extensions (comma-separated).
    #[arg(short, long, value_delimiter = ',', help_heading = "Files in output")]
    include: Vec<String>,

    /// Exclude these extensions (comma-separated).
    #[arg(short, long, value_delimiter = ',', help_heading = "Files in output")]
    exclude: Vec<String>,

    /// Follow .lnk shortcuts to their targets.
    #[arg(short, long, help_heading = "Files in output")]
    follow_lnk: bool,

    // === Content scan scope ===
    /// Extensions to scan for keywords (subset of -i). Takes EXTENSIONS, not search terms.
    #[arg(
        short = 'k',
        long,
        value_delimiter = ',',
        help_heading = "Content scan scope",
        long_help = "Extensions eligible for content scan, comma-separated.\n\
                     Must be a subset of --include. Empty = scan all in-scope files.\n\
                     Takes EXTENSIONS, not keywords. Search terms go in --keywords.\n\
                     Example: -i txt,log -k txt --keywords password"
    )]
    pub keyword_include: Vec<String>,

    /// Extensions never scanned (wins over -k).
    #[arg(long, value_delimiter = ',', help_heading = "Content scan scope")]
    pub keyword_exclude: Vec<String>,

    /// Max file size (bytes) scanned for keywords.
    #[arg(long, default_value_t = 10 * 1024 * 1024, help_heading = "Content scan scope")]
    pub max_scan_size: u64,

    // === Scan execution ===
    /// Number of worker threads for metadata and content scanning (1 = single-threaded).
    #[arg(
        long,
        default_value_t = 1,
        value_parser = parse_positive_usize,
        help_heading = "Scan execution"
    )]
    pub threads: usize,

    // === Search terms ===
    /// Literal search terms (comma-separated). THIS is the keyword flag.
    #[arg(long, value_delimiter = ',', help_heading = "Search terms")]
    pub keywords: Vec<String>,

    /// File of newline-separated literal keywords (# and blank lines ignored).
    #[arg(long, help_heading = "Search terms")]
    pub keywords_file: Option<PathBuf>,

    /// Regex pattern to search for. Repeat flag for multiple patterns.
    #[arg(long, long_help = KEYWORD_REGEX_LONG, help_heading = "Search terms")]
    pub keyword_regex: Vec<String>,

    /// Case-sensitive keyword/regex matching.
    #[arg(long, help_heading = "Search terms")]
    pub case_sensitive: bool,

    // === Match output ===
    /// Only emit files that had at least one keyword/regex hit.
    #[arg(long, help_heading = "Match output")]
    pub matches_only: bool,

    /// Lines of context above and below each match (0 = matched line only).
    #[arg(long, default_value_t = 1, help_heading = "Match output")]
    pub context_lines: usize,

    /// Words of context on the matched line, before and after the match (0 = full same-line prefix/suffix, no word clipping).
    #[arg(long, default_value_t = 8, help_heading = "Match output")]
    pub context_words: usize,

    /// Cap on MatchHits emitted per file (0 = unlimited). `matched_keywords` still lists every distinct hit.
    #[arg(long, default_value_t = 100, help_heading = "Match output")]
    pub max_matches_per_file: usize,

    /// Max characters per emitted context line/segment, not total before/after field size (0 = unlimited).
    #[arg(long, default_value_t = 0, help_heading = "Match output")]
    pub max_context_line_chars: usize,

    /// Replace repeated match context text with compact hashes and write --context-index-path at the end.
    #[arg(long, help_heading = "Match output")]
    pub hash_context_lines: bool,

    /// Update --context-index-path during the scan instead of only at the end.
    #[arg(long, help_heading = "Match output")]
    pub live_context_index: bool,

    // === Output ===
    /// Output JSON file.
    #[arg(short, long, default_value = "metadata.json", help_heading = "Output")]
    output_path: PathBuf,

    /// Output path for the sidecar context hash index written by --hash-context-lines.
    #[arg(long, help_heading = "Output")]
    context_index_path: Option<PathBuf>,

    /// Flush output to disk every N entries (0 = only at end).
    #[arg(long, default_value_t = 100, help_heading = "Output")]
    pub flush_every: u64,
}

impl Args {
    fn resolved_context_index_path(&self) -> PathBuf {
        self.context_index_path
            .clone()
            .unwrap_or_else(|| context_index::default_context_index_path(&self.output_path))
    }
}

fn parse_positive_usize(raw: &str) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|err| format!("invalid positive integer: {}", err))?;
    if value == 0 {
        Err("value must be greater than 0".to_string())
    } else {
        Ok(value)
    }
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
    writer
        .write_all(b"[")
        .expect("Unable to write to output file");

    // Init file counter
    let mut file_count: u64 = 0;
    let mut first_entry = true;
    let mut context_index = cli_args
        .hash_context_lines
        .then(context_index::ContextIndex::new);
    let context_index_path = context_index
        .as_ref()
        .map(|_| cli_args.resolved_context_index_path());
    if cli_args.live_context_index {
        if let (Some(index), Some(path)) = (context_index.as_ref(), context_index_path.as_deref()) {
            if let Err(err) = write_context_index_snapshot(index, path) {
                return (0, Err(err));
            }
        }
    }

    // Periodic flush cadence — push buffered bytes to disk every N entries so the
    // output file grows during the scan instead of appearing empty until the end.
    let flush_every = cli_args.flush_every;

    if cli_args.threads > 1 {
        return walk_path_parallel(
            cli_args,
            roots,
            scanner,
            writer,
            context_index,
            context_index_path,
            flush_every,
        );
    }

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
            .filter(|entry| should_include_path(cli_args, entry.path()))
        {
            // Create a serialized metadata entry
            let serialized_entry = match metadata::FileMetadata::metadata_from_path(entry.path()) {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("[!] {}", err);
                    continue;
                }
            };

            let entry_path = serialized_entry.full_path.clone();
            let is_lnk = serialized_entry.extension.eq("lnk");

            // Matches-only mode suppresses *writing* a file with no hits, but must NOT skip the
            // rest of the iteration — the .lnk-follow block below still has to resolve targets
            // (a .lnk file itself has no text hit, yet its target may have plenty).
            if let Some(mut serialized_entry) =
                enrich_entry_for_output(serialized_entry, cli_args, scanner)
            {
                let context_index_changed = if let Some(index) = context_index.as_mut() {
                    index.replace_match_contexts(&mut serialized_entry.matches)
                } else {
                    false
                };

                match emit_entry(
                    &mut writer,
                    &serialized_entry,
                    context_index_changed,
                    if cli_args.live_context_index {
                        context_index.as_ref()
                    } else {
                        None
                    },
                    if cli_args.live_context_index {
                        context_index_path.as_deref()
                    } else {
                        None
                    },
                    &mut first_entry,
                    &mut file_count,
                    flush_every,
                ) {
                    Ok(()) => {}
                    Err(EmitEntryError::ContextIndex(err)) => return (file_count, Err(err)),
                    Err(EmitEntryError::Output(err)) => eprintln!("[!] {}", err),
                }
            }

            // Check for .lnk files
            if is_lnk && cli_args.follow_lnk {
                // Clone this since this moves it out of context | We may need to use it later

                if entry_path.to_string_lossy().is_empty() {
                    eprintln!("The full path is empty.");
                    continue;
                }

                let path = std::path::Path::new(&entry_path);

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
                                    let serialized_entry =
                                        match metadata::FileMetadata::metadata_from_path(target) {
                                            Ok(value) => value,
                                            Err(err) => {
                                                eprintln!("[!] {}", err);
                                                continue;
                                            }
                                        };

                                    let Some(mut serialized_entry) = enrich_entry_for_output(
                                        serialized_entry,
                                        cli_args,
                                        scanner,
                                    ) else {
                                        continue;
                                    };

                                    let context_index_changed = if let Some(index) =
                                        context_index.as_mut()
                                    {
                                        index.replace_match_contexts(&mut serialized_entry.matches)
                                    } else {
                                        false
                                    };

                                    match emit_entry(
                                        &mut writer,
                                        &serialized_entry,
                                        context_index_changed,
                                        if cli_args.live_context_index {
                                            context_index.as_ref()
                                        } else {
                                            None
                                        },
                                        if cli_args.live_context_index {
                                            context_index_path.as_deref()
                                        } else {
                                            None
                                        },
                                        &mut first_entry,
                                        &mut file_count,
                                        flush_every,
                                    ) {
                                        Ok(()) => {}
                                        Err(EmitEntryError::ContextIndex(err)) => {
                                            return (file_count, Err(err));
                                        }
                                        Err(EmitEntryError::Output(err)) => {
                                            eprintln!("[!] {}", err)
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

    // Close the JSON array and force a final flush so the file is complete on disk.
    // Final-write failures are propagated to the caller so it can avoid claiming
    // success when either output file could not be completed on disk.
    let finalize = finalize_output_files(&mut writer).and_then(|_| {
        write_final_context_index(context_index.as_ref(), context_index_path.as_deref())
    });

    (file_count, finalize)
}

struct WorkItem {
    seq: u64,
    path: PathBuf,
}

struct WorkResult {
    seq: u64,
    entries: Vec<metadata::FileMetadata>,
    linked_dirs: Vec<LinkedDir>,
    errors: Vec<String>,
}

struct LinkedDir {
    source: PathBuf,
    target: PathBuf,
}

fn walk_path_parallel(
    cli_args: &Args,
    roots: &[PathBuf],
    scanner: &scanner::KeywordScanner,
    mut writer: BufWriter<File>,
    mut context_index: Option<context_index::ContextIndex>,
    context_index_path: Option<PathBuf>,
    flush_every: u64,
) -> (u64, std::io::Result<()>) {
    let mut file_count: u64 = 0;
    let mut first_entry = true;
    let mut queue: VecDeque<PathBuf> = roots.iter().cloned().collect();
    let mut visited_base_paths: HashSet<PathBuf> = HashSet::new();
    let mut next_seq = 0;
    let mut next_emit_seq = 0;
    let mut pending_results: BTreeMap<u64, WorkResult> = BTreeMap::new();
    let mut fatal_error: Option<io::Error> = None;

    let worker_count = cli_args.threads;
    let max_in_flight = worker_count.saturating_mul(8);
    let (work_tx, work_rx) = mpsc::channel::<Option<WorkItem>>();
    let (result_tx, result_rx) = mpsc::channel::<WorkResult>();
    let shared_work_rx = Arc::new(Mutex::new(work_rx));

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let work_rx = Arc::clone(&shared_work_rx);
            let result_tx = result_tx.clone();
            scope.spawn(move || loop {
                let message = {
                    let receiver = match work_rx.lock() {
                        Ok(receiver) => receiver,
                        Err(_) => break,
                    };
                    receiver.recv()
                };

                match message {
                    Ok(Some(item)) => {
                        let seq = item.seq;
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            process_work_item(item, cli_args, roots, scanner)
                        }))
                        .unwrap_or_else(|panic| WorkResult {
                            seq,
                            entries: Vec::new(),
                            linked_dirs: Vec::new(),
                            errors: vec![format!(
                                "worker panic while processing sequence {}: {}",
                                seq,
                                panic_message(panic.as_ref())
                            )],
                        });
                        if result_tx.send(result).is_err() {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            });
        }
        drop(result_tx);

        let mut in_flight = 0usize;
        while fatal_error.is_none() {
            let Some(current_base) = queue.pop_front() else {
                break;
            };

            for entry in WalkDir::new(&current_base)
                .into_iter()
                .filter_entry(|e| {
                    if e.file_type().is_dir() {
                        let path = e.path();

                        if visited_base_paths.contains(path) {
                            println!(
                                "[*] Skipping directory, since already visited: {}",
                                path.display()
                            );
                        }

                        !visited_base_paths.contains(path)
                    } else {
                        true
                    }
                })
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .filter(|entry| should_include_path(cli_args, entry.path()))
            {
                let item = WorkItem {
                    seq: next_seq,
                    path: entry.path().to_path_buf(),
                };
                next_seq += 1;

                if work_tx.send(Some(item)).is_err() {
                    fatal_error = Some(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "worker channel closed before scan completed",
                    ));
                    break;
                }
                in_flight += 1;

                while fatal_error.is_none() && in_flight >= max_in_flight {
                    match receive_parallel_result(
                        &result_rx,
                        &mut pending_results,
                        &mut next_emit_seq,
                        &mut writer,
                        context_index.as_mut(),
                        context_index_path.as_deref(),
                        cli_args.live_context_index,
                        &mut first_entry,
                        &mut file_count,
                        flush_every,
                        &mut queue,
                    ) {
                        Ok(()) => in_flight -= 1,
                        Err(err) => fatal_error = Some(err),
                    }
                }

                while fatal_error.is_none() && in_flight > 0 {
                    match result_rx.try_recv() {
                        Ok(result) => {
                            in_flight -= 1;
                            if let Err(err) = handle_parallel_result(
                                result,
                                &mut pending_results,
                                &mut next_emit_seq,
                                &mut writer,
                                context_index.as_mut(),
                                context_index_path.as_deref(),
                                cli_args.live_context_index,
                                &mut first_entry,
                                &mut file_count,
                                flush_every,
                                &mut queue,
                            ) {
                                fatal_error = Some(err);
                            }
                        }
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => {
                            fatal_error = Some(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "worker result channel closed before scan completed",
                            ));
                        }
                    }
                }
            }

            while fatal_error.is_none() && in_flight > 0 {
                match receive_parallel_result(
                    &result_rx,
                    &mut pending_results,
                    &mut next_emit_seq,
                    &mut writer,
                    context_index.as_mut(),
                    context_index_path.as_deref(),
                    cli_args.live_context_index,
                    &mut first_entry,
                    &mut file_count,
                    flush_every,
                    &mut queue,
                ) {
                    Ok(()) => in_flight -= 1,
                    Err(err) => fatal_error = Some(err),
                }
            }

            visited_base_paths.insert(current_base.clone());
        }

        for _ in 0..worker_count {
            let _ = work_tx.send(None);
        }
    });

    if let Some(err) = fatal_error {
        return (file_count, Err(err));
    }

    let finalize = finalize_output_files(&mut writer).and_then(|_| {
        write_final_context_index(context_index.as_ref(), context_index_path.as_deref())
    });
    (file_count, finalize)
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

fn should_include_path(cli_args: &Args, path: &Path) -> bool {
    let extension = path.extension().and_then(|ext| ext.to_str());
    let should_include = cli_args.include.is_empty()
        || extension.map_or(false, |ext| cli_args.include.contains(&ext.to_string()));
    let should_exclude = extension.map_or(false, |ext| cli_args.exclude.contains(&ext.to_string()));

    should_include && !should_exclude
}

fn process_work_item(
    item: WorkItem,
    cli_args: &Args,
    roots: &[PathBuf],
    scanner: &scanner::KeywordScanner,
) -> WorkResult {
    let mut result = WorkResult {
        seq: item.seq,
        entries: Vec::new(),
        linked_dirs: Vec::new(),
        errors: Vec::new(),
    };

    let serialized_entry = match metadata::FileMetadata::metadata_from_path(&item.path) {
        Ok(value) => value,
        Err(err) => {
            result.errors.push(err.to_string());
            return result;
        }
    };

    let entry_path = serialized_entry.full_path.clone();
    let is_lnk = serialized_entry.extension.eq("lnk");
    if let Some(entry) = enrich_entry_for_output(serialized_entry, cli_args, scanner) {
        result.entries.push(entry);
    }

    if is_lnk && cli_args.follow_lnk {
        if entry_path.to_string_lossy().is_empty() {
            result.errors.push("The full path is empty.".to_string());
            return result;
        }

        let lnk = match Lnk::try_from(entry_path.as_path()) {
            Ok(value) => value,
            Err(err) => {
                result.errors.push(format!("{:?}", err));
                return result;
            }
        };

        if let Some(target) = lnk.link_info.local_base_path {
            let target = Path::new(&target);

            if target.exists() {
                if target.is_file() {
                    if let Some(parent) = target.parent() {
                        if !roots.iter().any(|b| parent.starts_with(b)) {
                            match metadata::FileMetadata::metadata_from_path(target) {
                                Ok(entry) => {
                                    if let Some(entry) =
                                        enrich_entry_for_output(entry, cli_args, scanner)
                                    {
                                        result.entries.push(entry);
                                    }
                                }
                                Err(err) => result.errors.push(err.to_string()),
                            }
                        }
                    }
                } else if !roots.iter().any(|b| target.starts_with(b)) {
                    result.linked_dirs.push(LinkedDir {
                        source: entry_path.clone(),
                        target: target.to_path_buf(),
                    });
                }
            }
        }
    }

    result
}

fn enrich_entry_for_output(
    mut serialized_entry: metadata::FileMetadata,
    cli_args: &Args,
    scanner: &scanner::KeywordScanner,
) -> Option<metadata::FileMetadata> {
    if scanner.applies_to(&serialized_entry.extension) {
        let result = scanner.scan(&serialized_entry.full_path, serialized_entry.size);
        serialized_entry.matched_keywords = result.keywords;
        serialized_entry.matches = result.matches;
    }

    if cli_args.matches_only && serialized_entry.matched_keywords.is_empty() {
        None
    } else {
        Some(serialized_entry)
    }
}

fn receive_parallel_result(
    result_rx: &mpsc::Receiver<WorkResult>,
    pending_results: &mut BTreeMap<u64, WorkResult>,
    next_emit_seq: &mut u64,
    writer: &mut BufWriter<File>,
    context_index: Option<&mut context_index::ContextIndex>,
    context_index_path: Option<&Path>,
    live_context_index: bool,
    first_entry: &mut bool,
    file_count: &mut u64,
    flush_every: u64,
    queue: &mut VecDeque<PathBuf>,
) -> io::Result<()> {
    let result = result_rx.recv().map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "worker result channel closed before scan completed",
        )
    })?;

    handle_parallel_result(
        result,
        pending_results,
        next_emit_seq,
        writer,
        context_index,
        context_index_path,
        live_context_index,
        first_entry,
        file_count,
        flush_every,
        queue,
    )
}

fn handle_parallel_result(
    result: WorkResult,
    pending_results: &mut BTreeMap<u64, WorkResult>,
    next_emit_seq: &mut u64,
    writer: &mut BufWriter<File>,
    mut context_index: Option<&mut context_index::ContextIndex>,
    context_index_path: Option<&Path>,
    live_context_index: bool,
    first_entry: &mut bool,
    file_count: &mut u64,
    flush_every: u64,
    queue: &mut VecDeque<PathBuf>,
) -> io::Result<()> {
    pending_results.insert(result.seq, result);

    while let Some(result) = pending_results.remove(next_emit_seq) {
        for err in result.errors {
            eprintln!("[!] {}", err);
        }

        for mut entry in result.entries {
            let context_index_changed = if let Some(index) = context_index.as_deref_mut() {
                index.replace_match_contexts(&mut entry.matches)
            } else {
                false
            };

            match emit_entry(
                writer,
                &entry,
                context_index_changed,
                if live_context_index {
                    context_index.as_deref()
                } else {
                    None
                },
                if live_context_index {
                    context_index_path
                } else {
                    None
                },
                first_entry,
                file_count,
                flush_every,
            ) {
                Ok(()) => {}
                Err(EmitEntryError::ContextIndex(err)) => return Err(err),
                Err(EmitEntryError::Output(err)) => eprintln!("[!] {}", err),
            }
        }

        for linked_dir in result.linked_dirs {
            println!(
                "[*] Got lnk directory: {} -> {}",
                linked_dir.source.display(),
                linked_dir.target.display()
            );
            queue.push_back(linked_dir.target);
        }
        *next_emit_seq += 1;
    }

    Ok(())
}

fn finalize_output_files<W: Write>(writer: &mut W) -> std::io::Result<()> {
    writer.write_all(b"]")?;
    writer.flush()
}

fn write_final_context_index(
    index: Option<&context_index::ContextIndex>,
    path: Option<&Path>,
) -> std::io::Result<()> {
    if let (Some(index), Some(path)) = (index, path) {
        write_context_index_snapshot(index, path)?;
    }
    Ok(())
}

fn write_context_index_snapshot(
    index: &context_index::ContextIndex,
    path: &Path,
) -> std::io::Result<()> {
    index.write_to_path(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to write context index {}: {}", path.display(), err),
        )
    })
}

#[derive(Debug)]
enum EmitEntryError {
    ContextIndex(io::Error),
    Output(io::Error),
}

impl std::fmt::Display for EmitEntryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmitEntryError::ContextIndex(err) | EmitEntryError::Output(err) => {
                write!(formatter, "{}", err)
            }
        }
    }
}

fn emit_entry<W: Write>(
    writer: &mut W,
    entry: &metadata::FileMetadata,
    context_index_changed: bool,
    context_index: Option<&context_index::ContextIndex>,
    context_index_path: Option<&Path>,
    first_entry: &mut bool,
    file_count: &mut u64,
    flush_every: u64,
) -> Result<(), EmitEntryError> {
    if context_index_changed {
        if let (Some(index), Some(path)) = (context_index, context_index_path) {
            write_context_index_snapshot(index, path).map_err(EmitEntryError::ContextIndex)?;
        }
    }

    write_entry(writer, entry, first_entry, file_count, flush_every).map_err(EmitEntryError::Output)
}

/// Serialize a single entry into the open JSON array. Handles the comma separator
/// for all entries after the first, and triggers a periodic flush so readers tailing
/// the output file see progress during long scans.
fn write_entry<W: Write>(
    writer: &mut W,
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

/// Merge `--keywords` entries with `--keywords-file` file contents.
/// Dedupes exact matches while preserving first-seen order.
fn collect_keywords(args: &Args) -> Result<Vec<String>, String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();

    for k in &args.keywords {
        if seen.insert(k.clone()) {
            out.push(k.clone());
        }
    }

    if let Some(path) = &args.keywords_file {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("failed to read --keywords-file {}: {}", path.display(), e))?;
        for raw in contents.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if seen.insert(line.to_string()) {
                out.push(line.to_string());
            }
        }
    }

    Ok(out)
}

fn validate_output_paths(args: &Args) -> Result<(), String> {
    if args.live_context_index && !args.hash_context_lines {
        return Err("--live-context-index requires --hash-context-lines".to_string());
    }

    if args.hash_context_lines
        && normalized_output_path_for_compare(&args.resolved_context_index_path())?
            == normalized_output_path_for_compare(&args.output_path)?
    {
        return Err("--context-index-path must not equal --output-path".to_string());
    }
    Ok(())
}

fn normalized_output_path_for_compare(path: &Path) -> Result<String, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to resolve current directory: {}", e))?
            .join(path)
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }

    Ok(normalized
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase())
}

fn main() {
    let mut args = Args::parse();

    let roots = match collect_roots(&args) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("[!] {}", err);
            std::process::exit(2);
        }
    };

    args.keywords = match collect_keywords(&args) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("[!] {}", err);
            std::process::exit(2);
        }
    };

    if let Err(err) = validate_output_paths(&args) {
        eprintln!("[!] {}", err);
        std::process::exit(2);
    }

    let scanner = match scanner::KeywordScanner::new(&args) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("[!] Failed to build keyword scanner: {}", err);
            std::process::exit(2);
        }
    };

    let (file_count, finalize_result) = walk_path(&args, &roots, &scanner);

    if let Err(err) = finalize_result {
        eprintln!(
            "[!] Failed to finalize output files for {:?}: {} ({} entries written before failure)",
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

#[cfg(test)]
mod tests {
    use super::{emit_entry, validate_output_paths, walk_path, Args};
    use clap::Parser;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("directory-spider-{}-{}", name, suffix))
    }

    fn strip_volatile_timestamps(value: &mut Value) {
        for entry in value
            .as_array_mut()
            .expect("scan output is an array of metadata entries")
        {
            let entry = entry.as_object_mut().expect("metadata entry is an object");
            entry.remove("creation_time");
            entry.remove("last_access");
            entry.remove("last_write");
        }
    }

    #[test]
    fn hash_context_lines_flag_enables_default_sidecar_path() {
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "secret",
            "--hash-context-lines",
        ])
        .expect("arguments parse");

        assert!(args.hash_context_lines);
        assert_eq!(
            args.resolved_context_index_path(),
            PathBuf::from("metadata.context-index.json")
        );
    }

    #[test]
    fn context_index_path_overrides_default_sidecar_path() {
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "secret",
            "--hash-context-lines",
            "--context-index-path",
            "custom-index.json",
        ])
        .expect("arguments parse");

        assert_eq!(
            args.resolved_context_index_path(),
            PathBuf::from("custom-index.json")
        );
    }

    #[test]
    fn threads_default_to_single_threaded_and_accept_explicit_worker_count() {
        let default_args =
            Args::try_parse_from(["DirectorySpider", "-d", "C:\\Logs"]).expect("arguments parse");
        assert_eq!(default_args.threads, 1);

        let threaded_args =
            Args::try_parse_from(["DirectorySpider", "-d", "C:\\Logs", "--threads", "4"])
                .expect("arguments parse");
        assert_eq!(threaded_args.threads, 4);
    }

    #[test]
    fn threads_reject_zero_worker_count() {
        let err =
            match Args::try_parse_from(["DirectorySpider", "-d", "C:\\Logs", "--threads", "0"]) {
                Ok(_) => panic!("zero threads is invalid"),
                Err(err) => err,
            };

        assert!(err.to_string().contains("value must be greater than 0"));
    }

    #[test]
    fn threaded_scan_matches_single_threaded_output_in_matches_only_mode() {
        let base = unique_temp_dir("threaded-matches-only");
        let root = base.join("input");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("a.txt"), "before secret after").expect("write first fixture file");
        fs::write(root.join("b.txt"), "no searched content").expect("write second fixture file");
        fs::write(root.join("c.txt"), "token on another file").expect("write third fixture file");
        let single_output_path = base.join("single.json");
        let threaded_output_path = base.join("threaded.json");

        let single_args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            single_output_path.to_str().expect("output path is utf-8"),
            "--keywords",
            "secret,token",
            "--matches-only",
            "--threads",
            "1",
        ])
        .expect("arguments parse");
        let threaded_args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            threaded_output_path.to_str().expect("output path is utf-8"),
            "--keywords",
            "secret,token",
            "--matches-only",
            "--threads",
            "4",
        ])
        .expect("arguments parse");
        let single_scanner =
            crate::scanner::KeywordScanner::new(&single_args).expect("scanner builds");
        let threaded_scanner =
            crate::scanner::KeywordScanner::new(&threaded_args).expect("scanner builds");

        let (_single_count, single_result) =
            walk_path(&single_args, &[root.clone()], &single_scanner);
        let (_threaded_count, threaded_result) =
            walk_path(&threaded_args, &[root.clone()], &threaded_scanner);

        single_result.expect("single-threaded scan finalizes");
        threaded_result.expect("threaded scan finalizes");
        let mut single_output: Value = serde_json::from_str(
            &fs::read_to_string(&single_output_path).expect("single output exists"),
        )
        .expect("single output is valid json");
        let mut threaded_output: Value = serde_json::from_str(
            &fs::read_to_string(&threaded_output_path).expect("threaded output exists"),
        )
        .expect("threaded output is valid json");
        strip_volatile_timestamps(&mut single_output);
        strip_volatile_timestamps(&mut threaded_output);
        assert_eq!(threaded_output, single_output);
        fs::remove_dir_all(base).expect("remove fixture directory");
    }

    #[test]
    fn threaded_scan_matches_single_threaded_output_in_normal_mode() {
        let base = unique_temp_dir("threaded-normal");
        let root = base.join("input");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("a.txt"), "before secret after").expect("write first fixture file");
        fs::write(root.join("b.txt"), "no searched content").expect("write second fixture file");
        fs::write(root.join("c.log"), "token on another file").expect("write third fixture file");
        let single_output_path = base.join("single.json");
        let threaded_output_path = base.join("threaded.json");

        let single_args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            single_output_path.to_str().expect("output path is utf-8"),
            "--keywords",
            "secret,token",
            "--threads",
            "1",
        ])
        .expect("arguments parse");
        let threaded_args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            threaded_output_path.to_str().expect("output path is utf-8"),
            "--keywords",
            "secret,token",
            "--threads",
            "4",
        ])
        .expect("arguments parse");
        let single_scanner =
            crate::scanner::KeywordScanner::new(&single_args).expect("scanner builds");
        let threaded_scanner =
            crate::scanner::KeywordScanner::new(&threaded_args).expect("scanner builds");

        let (_single_count, single_result) =
            walk_path(&single_args, &[root.clone()], &single_scanner);
        let (_threaded_count, threaded_result) =
            walk_path(&threaded_args, &[root.clone()], &threaded_scanner);

        single_result.expect("single-threaded scan finalizes");
        threaded_result.expect("threaded scan finalizes");
        let mut single_output: Value = serde_json::from_str(
            &fs::read_to_string(&single_output_path).expect("single output exists"),
        )
        .expect("single output is valid json");
        let mut threaded_output: Value = serde_json::from_str(
            &fs::read_to_string(&threaded_output_path).expect("threaded output exists"),
        )
        .expect("threaded output is valid json");
        strip_volatile_timestamps(&mut single_output);
        strip_volatile_timestamps(&mut threaded_output);
        assert_eq!(threaded_output, single_output);
        assert_eq!(
            threaded_output
                .as_array()
                .expect("threaded output is an array")
                .len(),
            3
        );
        fs::remove_dir_all(base).expect("remove fixture directory");
    }

    #[test]
    fn threaded_hash_mode_writes_sidecar_before_hashed_entries() {
        let base = unique_temp_dir("threaded-sidecar-live-update");
        let root = base.join("input");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("a.txt"), "alpha secret first").expect("write first fixture file");
        fs::write(root.join("b.txt"), "bravo secret second").expect("write second fixture file");
        fs::write(root.join("c.txt"), "charlie secret third").expect("write third fixture file");
        let output_path = base.join("metadata.json");
        let sidecar_path = base.join("metadata.context-index.json");
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            output_path.to_str().expect("output path is utf-8"),
            "--keywords",
            "secret",
            "--matches-only",
            "--hash-context-lines",
            "--live-context-index",
            "--context-index-path",
            sidecar_path.to_str().expect("sidecar path is utf-8"),
            "--threads",
            "4",
        ])
        .expect("arguments parse");
        let scanner = crate::scanner::KeywordScanner::new(&args).expect("scanner builds");

        let (_file_count, result) = walk_path(&args, &[root.clone()], &scanner);

        result.expect("scan finalizes");
        let output: Value =
            serde_json::from_str(&fs::read_to_string(&output_path).expect("main output exists"))
                .expect("main output is valid json");
        let sidecar: Value =
            serde_json::from_str(&fs::read_to_string(&sidecar_path).expect("sidecar exists"))
                .expect("sidecar is valid json");
        let output = output.as_array().expect("main output is an array");
        assert_eq!(output.len(), 3);
        assert_eq!(output[0]["name"], Value::String("a.txt".to_string()));
        assert_eq!(output[1]["name"], Value::String("b.txt".to_string()));
        assert_eq!(output[2]["name"], Value::String("c.txt".to_string()));

        for (entry, before, after) in [
            (&output[0], "alpha ", " first"),
            (&output[1], "bravo ", " second"),
            (&output[2], "charlie ", " third"),
        ] {
            let hit = &entry["matches"][0];
            let before_hash = hit["before_hash"].as_str().expect("before hash exists");
            let after_hash = hit["after_hash"].as_str().expect("after hash exists");
            assert!(hit.get("before").is_none());
            assert!(hit.get("after").is_none());
            assert_eq!(
                sidecar["values"][before_hash],
                Value::String(before.to_string())
            );
            assert_eq!(
                sidecar["values"][after_hash],
                Value::String(after.to_string())
            );
        }
        fs::remove_dir_all(base).expect("remove fixture directory");
    }

    #[test]
    fn threaded_hash_mode_writes_final_sidecar_without_live_updates() {
        let base = unique_temp_dir("threaded-sidecar-final-update");
        let root = base.join("input");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("a.txt"), "alpha secret first").expect("write first fixture file");
        fs::write(root.join("b.txt"), "bravo secret second").expect("write second fixture file");
        fs::write(root.join("c.txt"), "charlie secret third").expect("write third fixture file");
        let output_path = base.join("metadata.json");
        let sidecar_path = base.join("metadata.context-index.json");
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            output_path.to_str().expect("output path is utf-8"),
            "--keywords",
            "secret",
            "--matches-only",
            "--hash-context-lines",
            "--context-index-path",
            sidecar_path.to_str().expect("sidecar path is utf-8"),
            "--threads",
            "4",
        ])
        .expect("arguments parse");
        let scanner = crate::scanner::KeywordScanner::new(&args).expect("scanner builds");

        let (_file_count, result) = walk_path(&args, &[root.clone()], &scanner);

        result.expect("scan finalizes");
        let output: Value =
            serde_json::from_str(&fs::read_to_string(&output_path).expect("main output exists"))
                .expect("main output is valid json");
        let sidecar: Value =
            serde_json::from_str(&fs::read_to_string(&sidecar_path).expect("sidecar exists"))
                .expect("sidecar is valid json");
        let output = output.as_array().expect("main output is an array");
        assert_eq!(output.len(), 3);

        for (entry, before, after) in [
            (&output[0], "alpha ", " first"),
            (&output[1], "bravo ", " second"),
            (&output[2], "charlie ", " third"),
        ] {
            let hit = &entry["matches"][0];
            let before_hash = hit["before_hash"].as_str().expect("before hash exists");
            let after_hash = hit["after_hash"].as_str().expect("after hash exists");
            assert_eq!(
                sidecar["values"][before_hash],
                Value::String(before.to_string())
            );
            assert_eq!(
                sidecar["values"][after_hash],
                Value::String(after.to_string())
            );
        }
        fs::remove_dir_all(base).expect("remove fixture directory");
    }

    #[test]
    fn hash_context_sidecar_path_cannot_match_output_path() {
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "secret",
            "--hash-context-lines",
            "-o",
            "metadata.json",
            "--context-index-path",
            "metadata.json",
        ])
        .expect("arguments parse");

        let err = validate_output_paths(&args).expect_err("matching paths are rejected");

        assert!(err.contains("--context-index-path must not equal --output-path"));
    }

    #[test]
    fn hash_context_sidecar_path_rejects_dot_alias_of_output_path() {
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "secret",
            "--hash-context-lines",
            "-o",
            "metadata.json",
            "--context-index-path",
            ".\\metadata.json",
        ])
        .expect("arguments parse");

        let err = validate_output_paths(&args).expect_err("matching paths are rejected");

        assert!(err.contains("--context-index-path must not equal --output-path"));
    }

    #[test]
    fn hash_context_sidecar_path_rejects_case_alias_of_output_path() {
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "secret",
            "--hash-context-lines",
            "-o",
            "metadata.json",
            "--context-index-path",
            "Metadata.json",
        ])
        .expect("arguments parse");

        let err = validate_output_paths(&args).expect_err("matching paths are rejected");

        assert!(err.contains("--context-index-path must not equal --output-path"));
    }

    #[test]
    fn live_context_index_requires_hash_context_lines() {
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "secret",
            "--live-context-index",
        ])
        .expect("arguments parse");

        let err = validate_output_paths(&args)
            .expect_err("live sidecar updates require hash context mode");

        assert!(err.contains("--live-context-index requires --hash-context-lines"));
    }

    #[test]
    fn hash_mode_writes_empty_sidecar_for_zero_context_scan() {
        let root = unique_temp_dir("empty-sidecar");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("notes.txt"), "no searched content").expect("write fixture file");
        let output_path = root.join("metadata.json");
        let sidecar_path = root.join("metadata.context-index.json");
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            output_path.to_str().expect("output path is utf-8"),
            "--hash-context-lines",
            "--context-index-path",
            sidecar_path.to_str().expect("sidecar path is utf-8"),
        ])
        .expect("arguments parse");
        let scanner = crate::scanner::KeywordScanner::new(&args).expect("scanner builds");

        let (_file_count, result) = walk_path(&args, &[root.clone()], &scanner);

        result.expect("scan finalizes");
        let sidecar = fs::read_to_string(&sidecar_path).expect("sidecar exists during scan");
        let sidecar: Value = serde_json::from_str(&sidecar).expect("sidecar is valid json");
        assert_eq!(sidecar["algorithm"], crate::context_index::ALGORITHM);
        assert_eq!(
            sidecar["values"]
                .as_object()
                .expect("values is an object")
                .len(),
            0
        );
        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn hash_mode_final_sidecar_failure_leaves_main_json_closed() {
        let root = unique_temp_dir("sidecar-final-failure");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("notes.txt"), "secret context").expect("write fixture file");
        let output_path = root.join("metadata.json");
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            output_path.to_str().expect("output path is utf-8"),
            "--keywords",
            "secret",
            "--matches-only",
            "--hash-context-lines",
            "--context-index-path",
            root.to_str().expect("temp path is utf-8"),
        ])
        .expect("arguments parse");
        let scanner = crate::scanner::KeywordScanner::new(&args).expect("scanner builds");

        let (file_count, result) = walk_path(&args, &[root.clone()], &scanner);

        let err = result.expect_err("directory path cannot be sidecar file");
        assert!(err.to_string().contains("failed to write context index"));
        assert_eq!(file_count, 1);
        let main_output = fs::read_to_string(&output_path).expect("main output was opened");
        let output: Value = serde_json::from_str(&main_output).expect("main output is valid json");
        assert_eq!(output.as_array().expect("main output is an array").len(), 1);
        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn live_hash_mode_sidecar_init_failure_leaves_main_json_unclosed() {
        let root = unique_temp_dir("sidecar-live-init-failure");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("notes.txt"), "secret context").expect("write fixture file");
        let output_path = root.join("metadata.json");
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            output_path.to_str().expect("output path is utf-8"),
            "--keywords",
            "secret",
            "--matches-only",
            "--hash-context-lines",
            "--live-context-index",
            "--context-index-path",
            root.to_str().expect("temp path is utf-8"),
        ])
        .expect("arguments parse");
        let scanner = crate::scanner::KeywordScanner::new(&args).expect("scanner builds");

        let (file_count, result) = walk_path(&args, &[root.clone()], &scanner);

        let err = result.expect_err("directory path cannot be sidecar file");
        assert!(err.to_string().contains("failed to write context index"));
        assert_eq!(file_count, 0);
        let main_output = fs::read_to_string(&output_path).expect("main output was opened");
        assert_eq!(main_output, "[");
        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn hash_mode_updates_sidecar_with_match_contexts_during_scan() {
        let base = unique_temp_dir("sidecar-live-update");
        let root = base.join("input");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("notes.txt"), "before secret after").expect("write fixture file");
        let output_path = base.join("metadata.json");
        let sidecar_path = base.join("metadata.context-index.json");
        let args = Args::try_parse_from([
            "DirectorySpider",
            "-d",
            root.to_str().expect("temp path is utf-8"),
            "-o",
            output_path.to_str().expect("output path is utf-8"),
            "--keywords",
            "secret",
            "--matches-only",
            "--hash-context-lines",
            "--context-index-path",
            sidecar_path.to_str().expect("sidecar path is utf-8"),
        ])
        .expect("arguments parse");
        let scanner = crate::scanner::KeywordScanner::new(&args).expect("scanner builds");

        let (_file_count, result) = walk_path(&args, &[root.clone()], &scanner);

        result.expect("scan finalizes");
        let output: Value =
            serde_json::from_str(&fs::read_to_string(&output_path).expect("main output exists"))
                .expect("main output is valid json");
        let sidecar: Value =
            serde_json::from_str(&fs::read_to_string(&sidecar_path).expect("sidecar exists"))
                .expect("sidecar is valid json");
        let hit = &output[0]["matches"][0];
        let before_hash = hit["before_hash"].as_str().expect("before hash exists");
        let after_hash = hit["after_hash"].as_str().expect("after hash exists");
        assert!(hit.get("before").is_none());
        assert!(hit.get("after").is_none());
        assert_eq!(
            sidecar["values"][before_hash],
            Value::String("before ".to_string())
        );
        assert_eq!(
            sidecar["values"][after_hash],
            Value::String(" after".to_string())
        );
        fs::remove_dir_all(base).expect("remove fixture directory");
    }

    #[test]
    fn emit_entry_does_not_write_hash_entry_when_sidecar_snapshot_fails() {
        let base = unique_temp_dir("sidecar-emit-failure");
        fs::create_dir_all(&base).expect("create fixture directory");
        let file_path = base.join("notes.txt");
        fs::write(&file_path, "before secret after").expect("write fixture file");
        let mut entry =
            crate::metadata::FileMetadata::metadata_from_path(&file_path).expect("metadata builds");
        entry.matched_keywords = vec!["secret".to_string()];
        entry.matches = vec![crate::metadata::MatchHit {
            keyword: "secret".to_string(),
            line: 1,
            column: 8,
            before: "before ".to_string(),
            r#match: "secret".to_string(),
            after: " after".to_string(),
            before_hash: None,
            after_hash: None,
        }];
        let mut index = crate::context_index::ContextIndex::new();
        let changed = index.replace_match_contexts(&mut entry.matches);
        let mut writer = Vec::from(&b"["[..]);
        let mut first_entry = true;
        let mut file_count = 0;

        let err = emit_entry(
            &mut writer,
            &entry,
            changed,
            Some(&index),
            Some(&base),
            &mut first_entry,
            &mut file_count,
            0,
        )
        .expect_err("sidecar snapshot cannot persist over directory");

        assert!(err.to_string().contains("failed to write context index"));
        assert_eq!(String::from_utf8(writer).unwrap(), "[");
        assert!(first_entry);
        assert_eq!(file_count, 0);
        fs::remove_dir_all(base).expect("remove fixture directory");
    }

    #[test]
    fn emit_entry_writes_sidecar_that_resolves_streamed_hashes() {
        let base = unique_temp_dir("sidecar-emit-invariant");
        fs::create_dir_all(&base).expect("create fixture directory");
        let file_path = base.join("notes.txt");
        fs::write(&file_path, "before secret after").expect("write fixture file");
        let sidecar_path = base.join("context-index.json");
        let mut entry =
            crate::metadata::FileMetadata::metadata_from_path(&file_path).expect("metadata builds");
        entry.matched_keywords = vec!["secret".to_string()];
        entry.matches = vec![crate::metadata::MatchHit {
            keyword: "secret".to_string(),
            line: 1,
            column: 8,
            before: "before ".to_string(),
            r#match: "secret".to_string(),
            after: " after".to_string(),
            before_hash: None,
            after_hash: None,
        }];
        let mut index = crate::context_index::ContextIndex::new();
        let changed = index.replace_match_contexts(&mut entry.matches);
        let mut writer = Vec::from(&b"["[..]);
        let mut first_entry = true;
        let mut file_count = 0;

        emit_entry(
            &mut writer,
            &entry,
            changed,
            Some(&index),
            Some(&sidecar_path),
            &mut first_entry,
            &mut file_count,
            0,
        )
        .expect("entry emits");

        writer.push(b']');
        let output: Value =
            serde_json::from_slice(&writer).expect("streamed output fragment is valid json");
        let sidecar: Value =
            serde_json::from_str(&fs::read_to_string(&sidecar_path).expect("sidecar exists"))
                .expect("sidecar is valid json");
        let hit = &output[0]["matches"][0];
        let before_hash = hit["before_hash"].as_str().expect("before hash exists");
        let after_hash = hit["after_hash"].as_str().expect("after hash exists");
        assert_eq!(
            sidecar["values"][before_hash],
            Value::String("before ".to_string())
        );
        assert_eq!(
            sidecar["values"][after_hash],
            Value::String(" after".to_string())
        );
        assert_eq!(file_count, 1);
        fs::remove_dir_all(base).expect("remove fixture directory");
    }
}
