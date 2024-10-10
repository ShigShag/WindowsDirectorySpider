use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs;
use std::fs::File;
use std::fs::Permissions;
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use struson::writer::{JsonStreamWriter, JsonWriter};
use walkdir::WalkDir;

#[derive(Serialize)]
struct FileMetadata {
    name: String,
    path: String,
    size: u64,
    created: Option<String>,
    modified: Option<String>,
    accessed: Option<String>,
    owner: Option<u32>,
    permissions: Option<u32>,
    file_type: String,
}

impl FileMetadata {
    // Extract metadata from a given path
    fn from_path(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;
        let file_type = if metadata.is_file() {
            "File".to_string()
        } else if metadata.is_dir() {
            "Directory".to_string()
        } else {
            "Other".to_string()
        };

        Some(FileMetadata {
            name: path.file_name()?.to_string_lossy().to_string(),
            path: path.display().to_string(),
            size: metadata.len(),
            created: metadata.created().ok().map(|time| format_time(time)),
            modified: metadata.modified().ok().map(|time| format_time(time)),
            accessed: metadata.accessed().ok().map(|time| format_time(time)),
            owner: Some(metadata.uid()),
            permissions: Some(metadata.permissions().mode()),
            file_type,
        })
    }
}

// Function to format file times into readable strings
fn format_time(time: std::time::SystemTime) -> String {
    let datetime: DateTime<Utc> = time.into();
    datetime.to_rfc3339()
}

fn walk_path(base_path: &String) {
    let file = File::create("metadata.json").expect("Unable to open file");
    let mut writer = BufWriter::new(file);
    let mut json_writer = JsonStreamWriter::new(&mut writer);
    json_writer.begin_array().unwrap();
    // Walk path with walkdir and filter out directories
    for entry in WalkDir::new(base_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    // Only keep non-directories
    {
        if let Some(metadata) = FileMetadata::from_path(entry.path()) {
            json_writer.serialize_value(&metadata).unwrap();
        }
    }
    json_writer.end_array().unwrap();
    json_writer.finish_document().unwrap();
}

fn main() {
    walk_path(&"./".to_string());
}
