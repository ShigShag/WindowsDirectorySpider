use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
use std::ffi::OsStr;
use std::io::{Error, ErrorKind};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::DirEntry;

use super::helper;

pub struct MatchHit {
    pub keyword: String,
    pub line: usize,
    pub column: usize,
    pub before: String,
    pub r#match: String,
    pub after: String,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
}

impl MatchHit {
    pub fn replace_context_with_hashes(&mut self, index: &mut crate::context_index::ContextIndex) {
        self.before_hash = Some(index.insert(&self.before));
        self.after_hash = Some(index.insert(&self.after));
        debug_assert!(self.before_hash.is_some() && self.after_hash.is_some());
        self.before.clear();
        self.after.clear();
    }
}

impl Serialize for MatchHit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MatchHit", 6)?;
        state.serialize_field("keyword", &self.keyword)?;
        state.serialize_field("line", &self.line)?;
        state.serialize_field("column", &self.column)?;
        // Hash mode sets both context refs together; mixed inline/hash output is invalid.
        debug_assert_eq!(self.before_hash.is_some(), self.after_hash.is_some());
        if let (Some(before_hash), Some(after_hash)) = (&self.before_hash, &self.after_hash) {
            state.serialize_field("before_hash", before_hash)?;
            state.serialize_field("match", &self.r#match)?;
            state.serialize_field("after_hash", after_hash)?;
        } else {
            state.serialize_field("before", &self.before)?;
            state.serialize_field("match", &self.r#match)?;
            state.serialize_field("after", &self.after)?;
        }
        state.end()
    }
}

#[derive(Serialize)]
pub struct FileMetadata {
    name: String,
    pub full_path: PathBuf,
    pub extension: String,
    pub(crate) size: u64,
    creation_time: String,
    last_access: String,
    last_write: String,
    is_read_only: bool,
    pub matched_keywords: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<MatchHit>,
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
            matched_keywords: Vec::new(),
            matches: Vec::new(),
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
            matched_keywords: Vec::new(),
            matches: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::MatchHit;
    use crate::context_index::ContextIndex;
    use serde_json::Value;

    fn sample_hit() -> MatchHit {
        MatchHit {
            keyword: "secret".to_string(),
            line: 3,
            column: 12,
            before: "before context".to_string(),
            r#match: "secret".to_string(),
            after: "after context".to_string(),
            before_hash: None,
            after_hash: None,
        }
    }

    #[test]
    fn default_match_serialization_keeps_inline_context() {
        let value = serde_json::to_value(sample_hit()).expect("hit serializes");

        assert_eq!(value["before"], Value::String("before context".to_string()));
        assert_eq!(value["match"], Value::String("secret".to_string()));
        assert_eq!(value["after"], Value::String("after context".to_string()));
        assert!(value.get("before_hash").is_none());
        assert!(value.get("after_hash").is_none());
    }

    #[test]
    fn hash_mode_serialization_uses_hash_fields_without_inline_context() {
        let mut index = ContextIndex::new();
        let mut hit = sample_hit();

        hit.replace_context_with_hashes(&mut index);
        let value = serde_json::to_value(hit).expect("hit serializes");

        assert!(value.get("before").is_none());
        assert!(value.get("after").is_none());
        assert_eq!(value["match"], Value::String("secret".to_string()));
        assert_eq!(
            value["before_hash"].as_str().unwrap().len(),
            "b3:".len() + 22
        );
        assert_eq!(
            value["after_hash"].as_str().unwrap().len(),
            "b3:".len() + 22
        );
        assert_eq!(index.len(), 2);
    }
}
