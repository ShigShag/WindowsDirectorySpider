use serde::Serialize;
use std::ffi::OsStr;
use std::os::windows::fs::MetadataExt;
use std::path::PathBuf;
use walkdir::DirEntry;
use std::io::{Error, ErrorKind};

use super::helper;

#[derive(Serialize)]
pub struct FileMetadata {
    name: String,
    full_path: PathBuf,
    extension: String,
    size: u64,
    creation_time: String,
    last_access: String,
    last_write: String,
    is_read_only: bool,
}

impl FileMetadata {
    // Extract metadata from a given path
    pub fn from_fs_metadata(dir_entry: &DirEntry) -> Result<Self, std::io::Error> {
        let metadata = match dir_entry.metadata() {
            Ok(value) => value,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Metadata could not be parsed")),
        };

        // Extract path and name if it fails save empty path
        // let file_path = dir_entry.path().into_os_string().into_string().unwrap_or(String::from(""));
        let file_name = dir_entry
            .file_name()
            .to_str()
            .unwrap_or_else(|| "")
            .to_string();
        let file_path = dir_entry.path().into();
        let file_extension = dir_entry
            .path()
            .extension()
            .and_then(OsStr::to_str)
            .map(|ext| ext.to_string())
            .unwrap_or_else(|| String::from(""));
        let file_size = metadata.file_size();
        let creation_time_str = match helper::format_system_time(metadata.created()) {
            Some(time) => time,
            None => String::from("/Date(0)/"), // Use default if creation time is unavailable
        };
        let last_modified_time_str = match helper::format_system_time(metadata.accessed()) {
            Some(time) => time,
            None => String::from("/Date(0)/"),
        };
        let last_write_time_str = match helper::format_system_time(metadata.modified()) {
            Some(time) => time,
            None => String::from("/Date(0)/"),
        };
        let file_is_readonly = metadata.permissions().readonly();

        Ok(FileMetadata {
            name: file_name,
            full_path: file_path,
            extension: file_extension,
            size: file_size,
            creation_time: creation_time_str,
            last_access: last_modified_time_str,
            last_write: last_write_time_str,
            is_read_only: file_is_readonly,
        })
    }
}
