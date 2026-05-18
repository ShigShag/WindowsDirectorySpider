use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::metadata::MatchHit;

pub const ALGORITHM: &str = "blake3-128-base64url-no-pad";

#[derive(Default)]
pub struct ContextIndex {
    values: BTreeMap<String, String>,
}

impl ContextIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, value: &str) -> String {
        let key = hash_context(value);
        self.values
            .entry(key.clone())
            .or_insert_with(|| value.to_string());
        key
    }

    pub fn replace_match_contexts(&mut self, matches: &mut [MatchHit]) {
        for hit in matches {
            hit.replace_context_with_hashes(self);
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn write_to_path(&self, path: &Path) -> std::io::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, self)?;
        writer.flush()
    }
}

impl Serialize for ContextIndex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ContextIndex", 2)?;
        state.serialize_field("algorithm", ALGORITHM)?;
        state.serialize_field("values", &self.values)?;
        state.end()
    }
}

fn hash_context(value: &str) -> String {
    let hash = blake3::hash(value.as_bytes());
    let compact = URL_SAFE_NO_PAD.encode(&hash.as_bytes()[..16]);
    format!("b3:{}", compact)
}

pub fn default_context_index_path(output_path: &Path) -> PathBuf {
    let stem = output_path
        .file_stem()
        .or_else(|| output_path.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("metadata");

    let mut index_path = output_path.to_path_buf();
    index_path.set_file_name(format!("{}.context-index.json", stem));
    index_path
}

#[cfg(test)]
mod tests {
    use super::{default_context_index_path, ContextIndex, ALGORITHM};
    use serde_json::Value;
    use std::path::Path;

    #[test]
    fn duplicate_context_values_reuse_one_compact_hash() {
        let mut index = ContextIndex::new();

        let first = index.insert("same context");
        let second = index.insert("same context");

        assert_eq!(first, second);
        assert_eq!(first.len(), "b3:".len() + 22);
        assert!(first.starts_with("b3:"));
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn different_context_values_get_separate_hashes() {
        let mut index = ContextIndex::new();

        let first = index.insert("first context");
        let second = index.insert("second context");

        assert_ne!(first, second);
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn sidecar_serialization_contains_algorithm_and_values() {
        let mut index = ContextIndex::new();
        let key = index.insert("full context text");

        let json = serde_json::to_value(&index).expect("index serializes");

        assert_eq!(json["algorithm"], ALGORITHM);
        assert_eq!(
            json["values"][key],
            Value::String("full context text".to_string())
        );
    }

    #[test]
    fn hashing_match_contexts_dedupes_repeated_contexts() {
        let mut index = ContextIndex::new();
        let mut hits = vec![
            crate::metadata::MatchHit {
                keyword: "secret".to_string(),
                line: 1,
                column: 8,
                before: "same before ".to_string(),
                r#match: "secret".to_string(),
                after: " same after".to_string(),
                before_hash: None,
                after_hash: None,
            },
            crate::metadata::MatchHit {
                keyword: "secret".to_string(),
                line: 2,
                column: 8,
                before: "same before ".to_string(),
                r#match: "secret".to_string(),
                after: " same after".to_string(),
                before_hash: None,
                after_hash: None,
            },
        ];

        index.replace_match_contexts(&mut hits);

        assert_eq!(hits[0].before_hash, hits[1].before_hash);
        assert_eq!(hits[0].after_hash, hits[1].after_hash);
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn default_index_path_uses_output_stem() {
        assert_eq!(
            default_context_index_path(Path::new("metadata.json")),
            Path::new("metadata.context-index.json")
        );
        assert_eq!(
            default_context_index_path(Path::new("nested/out.json")),
            Path::new("nested/out.context-index.json")
        );
        assert_eq!(
            default_context_index_path(Path::new("metadata")),
            Path::new("metadata.context-index.json")
        );
    }
}
