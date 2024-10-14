use clap::Parser;
use parselnk::Lnk;
use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use struson::writer::{JsonStreamWriter, JsonWriter};
use walkdir::WalkDir;

mod helper;
mod metadata;

/// Command line argument parser
#[derive(Parser)]
struct Args {
    /// The base directory to start parsing recursively
    #[arg(short, long)]
    directory_path: PathBuf,

    /// Output JSON file (default: metadata.json)
    #[arg(short, long, default_value = "metadata.json")]
    output_path: PathBuf,

    /// Include these file extensions, comma-separated (e.g., "exe,txt")
    #[arg(short, long, value_delimiter = ',')]
    include: Vec<String>,

    /// Exclude these file extensions, comma-separated (e.g., "iso")
    #[arg(short, long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Follow .lnk files (default: false)
    #[arg(short, long)]
    follow_lnk: bool,
}

fn walk_path(cli_args: &Args) -> u64 {
    // Check if path to walk exists
    if !&cli_args.directory_path.exists() {
        eprintln!(
            "Directory path {:?} does not exist or is not a valid directory.",
            &cli_args.directory_path
        );
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

    // Add the initial base directory to the queue
    queue.push_back(cli_args.directory_path.clone());

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
            let serialized_entry = match metadata::FileMetadata::metadata_from_dir_entry(&entry) {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("[!] {}", err);
                    continue;
                }
            };

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
                                if !parent.starts_with(cli_args.directory_path.clone()) {
                                    // Get metadata | Same procedure as with normal files
                                    let serialized_entry =
                                        match metadata::FileMetadata::metadata_from_path(target) {
                                            Ok(value) => value,
                                            Err(err) => {
                                                eprintln!("[!] {}", err);
                                                continue;
                                            }
                                        };

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
                            if !target.starts_with(cli_args.directory_path.clone()) {
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

fn main() {
    let args = Args::parse();

    let file_count = walk_path(&args);

    if file_count > 0 {
        println!(
            "[+] Metadata of {} files has been saved to {:?}",
            file_count, args.output_path
        );
    }
}
