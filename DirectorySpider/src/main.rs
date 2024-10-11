use clap::Parser;
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
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

    // Walk path with walkdir and filter out directories
    for entry in WalkDir::new(&cli_args.directory_path)
        .into_iter()
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
        let serialized_entry = match metadata::FileMetadata::from_fs_metadata(&entry) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("{}", err);
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
                eprintln!("{}", err);
            }
        }
    }

    // Also escape this error to try and finish the document
    if let Err(err) = json_writer.end_array() {
        eprintln!("Error ending JSON array: {}", err);
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
            "Metadata of {} files has been saved to {:?}",
            file_count, args.output_path
        );
    }
}
