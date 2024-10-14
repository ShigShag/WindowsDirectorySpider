use serde::Serialize;
use std::ffi::OsStr;
use std::io::{Error, ErrorKind};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::DirEntry;

use super::helper;

#[derive(Serialize)]
pub struct FileMetadata {
    name: String,
    pub full_path: PathBuf,
    pub extension: String,
    size: u64,
    creation_time: String,
    last_access: String,
    last_write: String,
    is_read_only: bool,
}

impl FileMetadata {
    // Extract metadata from a given path
    pub fn metadata_from_dir_entry(dir_entry: &DirEntry) -> Result<Self, std::io::Error> {
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
        let creation_time_str =
            helper::format_system_time(metadata.created()).unwrap_or("/Date(0)/".to_string());
        let last_access_time_str =
            helper::format_system_time(metadata.accessed()).unwrap_or("/Date(0)/".to_string());
        let last_write_time_str =
            helper::format_system_time(metadata.modified()).unwrap_or("/Date(0)/".to_string());
        let file_is_readonly = metadata.permissions().readonly();

        Ok(FileMetadata {
            name: file_name,
            full_path: file_path,
            extension: file_extension,
            size: file_size,
            creation_time: creation_time_str,
            last_access: last_access_time_str,
            last_write: last_write_time_str,
            is_read_only: file_is_readonly,
        })
    }

    pub fn metadata_from_path(path: &Path) -> Result<Self, std::io::Error> {
        let metadata = match path.metadata() {
            Ok(value) => value,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Metadata could not be parsed")),
        };

        let file_name = path
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("")
            .to_string();
        let file_path = path.to_path_buf();
        let file_extension = path
            .extension()
            .and_then(OsStr::to_str)
            .map(|ext| ext.to_string())
            .unwrap_or_else(|| String::from(""));
        let file_size = metadata.file_size();
        let creation_time_str =
            helper::format_system_time(metadata.created()).unwrap_or("/Date(0)/".to_string());
        let last_access_time_str =
            helper::format_system_time(metadata.accessed()).unwrap_or("/Date(0)/".to_string());
        let last_write_time_str =
            helper::format_system_time(metadata.modified()).unwrap_or("/Date(0)/".to_string());
        let file_is_readonly = metadata.permissions().readonly();

        Ok(FileMetadata {
            name: file_name,
            full_path: file_path,
            extension: file_extension,
            size: file_size,
            creation_time: creation_time_str,
            last_access: last_access_time_str,
            last_write: last_write_time_str,
            is_read_only: file_is_readonly,
        })
    }
}
