use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::Args;

pub struct KeywordScanner {
    literals: Vec<String>,
    literals_lc: Vec<String>,
    regexes: Vec<Regex>,
    regex_patterns: Vec<String>,
    include_exts: Vec<String>,
    exclude_exts: Vec<String>,
    case_sensitive: bool,
    max_scan_size: u64,
    enabled: bool,
}

impl KeywordScanner {
    pub fn new(args: &Args) -> Result<Self, regex::Error> {
        let literals: Vec<String> = args.keywords.iter().map(|s| s.to_string()).collect();
        let literals_lc: Vec<String> = literals.iter().map(|s| s.to_lowercase()).collect();

        let regex_patterns: Vec<String> =
            args.keyword_regex.iter().map(|s| s.to_string()).collect();

        let mut regexes: Vec<Regex> = Vec::with_capacity(regex_patterns.len());
        for pat in &regex_patterns {
            let effective = if args.case_sensitive {
                pat.clone()
            } else {
                format!("(?i){}", pat)
            };
            regexes.push(Regex::new(&effective)?);
        }

        let enabled = !literals.is_empty() || !regexes.is_empty();

        Ok(KeywordScanner {
            literals,
            literals_lc,
            regexes,
            regex_patterns,
            include_exts: args.keyword_include.clone(),
            exclude_exts: args.keyword_exclude.clone(),
            case_sensitive: args.case_sensitive,
            max_scan_size: args.max_scan_size,
            enabled,
        })
    }

    pub fn applies_to(&self, ext: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let ext_owned = ext.to_string();
        let included = self.include_exts.is_empty() || self.include_exts.contains(&ext_owned);
        let excluded = self.exclude_exts.contains(&ext_owned);
        included && !excluded
    }

    pub fn scan(&self, path: &Path, file_size: u64) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        if file_size > self.max_scan_size {
            eprintln!(
                "[*] Skipping scan, file exceeds --max-scan-size ({} > {}): {}",
                file_size,
                self.max_scan_size,
                path.display()
            );
            return Vec::new();
        }

        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("[!] scan read {}: {}", path.display(), err);
                return Vec::new();
            }
        };

        let content = String::from_utf8_lossy(&bytes);

        let mut hits: HashSet<String> = HashSet::new();

        if !self.literals.is_empty() {
            if self.case_sensitive {
                for (i, needle) in self.literals.iter().enumerate() {
                    if content.contains(needle.as_str()) {
                        hits.insert(self.literals[i].clone());
                    }
                }
            } else {
                let haystack_lc = content.to_lowercase();
                for (i, needle_lc) in self.literals_lc.iter().enumerate() {
                    if haystack_lc.contains(needle_lc.as_str()) {
                        hits.insert(self.literals[i].clone());
                    }
                }
            }
        }

        for (i, re) in self.regexes.iter().enumerate() {
            if re.is_match(&content) {
                hits.insert(self.regex_patterns[i].clone());
            }
        }

        hits.into_iter().collect()
    }
}
