use regex::{Regex, RegexBuilder};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::Args;
use crate::metadata::MatchHit;

pub struct ScanResult {
    pub keywords: Vec<String>,
    pub matches: Vec<MatchHit>,
}

pub struct KeywordScanner {
    compiled: Vec<(String, Regex)>,
    include_exts: Vec<String>,
    exclude_exts: Vec<String>,
    max_scan_size: u64,
    enabled: bool,
    context_lines: usize,
    context_words: usize,
    max_matches: usize,
}

impl KeywordScanner {
    pub fn new(args: &Args) -> Result<Self, regex::Error> {
        let mut compiled: Vec<(String, Regex)> =
            Vec::with_capacity(args.keywords.len() + args.keyword_regex.len());

        for needle in &args.keywords {
            let pattern = regex::escape(needle);
            let regex = RegexBuilder::new(&pattern)
                .case_insensitive(!args.case_sensitive)
                .build()?;
            compiled.push((needle.clone(), regex));
        }

        for pat in &args.keyword_regex {
            let effective = if args.case_sensitive {
                pat.clone()
            } else {
                format!("(?i){}", pat)
            };
            compiled.push((pat.clone(), Regex::new(&effective)?));
        }

        let enabled = !compiled.is_empty();

        Ok(KeywordScanner {
            compiled,
            include_exts: args.keyword_include.clone(),
            exclude_exts: args.keyword_exclude.clone(),
            max_scan_size: args.max_scan_size,
            enabled,
            context_lines: args.context_lines,
            context_words: args.context_words,
            max_matches: args.max_matches_per_file,
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

    pub fn scan(&self, path: &Path, file_size: u64) -> ScanResult {
        if !self.enabled {
            return ScanResult { keywords: Vec::new(), matches: Vec::new() };
        }

        if file_size > self.max_scan_size {
            eprintln!(
                "[*] Skipping scan, file exceeds --max-scan-size ({} > {}): {}",
                file_size,
                self.max_scan_size,
                path.display()
            );
            return ScanResult { keywords: Vec::new(), matches: Vec::new() };
        }

        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("[!] scan read {}: {}", path.display(), err);
                return ScanResult { keywords: Vec::new(), matches: Vec::new() };
            }
        };

        let content = String::from_utf8_lossy(&bytes);
        let line_starts = compute_line_starts(&content);

        let mut keywords: Vec<String> = Vec::new();
        let mut seen_keywords: HashSet<String> = HashSet::new();
        let mut matches: Vec<MatchHit> = Vec::new();
        let cap_unlimited = self.max_matches == 0;

        for (display, regex) in &self.compiled {
            for m in regex.find_iter(&content) {
                if seen_keywords.insert(display.clone()) {
                    keywords.push(display.clone());
                }
                if cap_unlimited || matches.len() < self.max_matches {
                    matches.push(build_hit(
                        &content,
                        &line_starts,
                        m.start(),
                        m.end(),
                        display,
                        self.context_lines,
                        self.context_words,
                    ));
                }
            }
        }

        ScanResult { keywords, matches }
    }
}

fn compute_line_starts(content: &str) -> Vec<usize> {
    let mut starts = Vec::with_capacity(content.len() / 40 + 1);
    starts.push(0);
    for (i, b) in content.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

fn build_hit(
    content: &str,
    line_starts: &[usize],
    match_start: usize,
    match_end: usize,
    keyword: &str,
    context_lines: usize,
    context_words: usize,
) -> MatchHit {
    let start_line_idx = line_starts
        .partition_point(|&s| s <= match_start)
        .saturating_sub(1);

    let end_anchor = match_end.saturating_sub(1).max(match_start);
    let end_line_idx = line_starts
        .partition_point(|&s| s <= end_anchor)
        .saturating_sub(1);

    let above_start = line_starts[start_line_idx.saturating_sub(context_lines)];
    let below_end = line_starts
        .get(end_line_idx + 1 + context_lines)
        .copied()
        .unwrap_or(content.len());

    let raw_before = &content[above_start..match_start];
    let raw_after = &content[match_end..below_end];

    let prefix_split = raw_before.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let above_portion = &raw_before[..prefix_split];
    let matched_line_prefix = &raw_before[prefix_split..];
    let clipped_prefix = clip_prefix_words(matched_line_prefix, context_words);

    let suffix_split = raw_after.find('\n').unwrap_or(raw_after.len());
    let matched_line_suffix = &raw_after[..suffix_split];
    let below_portion = &raw_after[suffix_split..];
    let clipped_suffix = clip_suffix_words(matched_line_suffix, context_words);

    let mut before = String::with_capacity(above_portion.len() + clipped_prefix.len());
    before.push_str(above_portion);
    before.push_str(clipped_prefix);

    let mut after = String::with_capacity(clipped_suffix.len() + below_portion.len());
    after.push_str(clipped_suffix);
    after.push_str(below_portion);

    let matched_text = content[match_start..match_end].to_string();
    let line = start_line_idx + 1;
    let column = match_start - line_starts[start_line_idx] + 1;

    MatchHit {
        keyword: keyword.to_string(),
        line,
        column,
        before,
        r#match: matched_text,
        after,
    }
}

/// Keep the last `n` whitespace-separated words of `text`. `n == 0` returns the whole slice.
/// Walks bytes from the right so original whitespace is preserved exactly.
fn clip_prefix_words(text: &str, n: usize) -> &str {
    if n == 0 || text.is_empty() {
        return text;
    }
    let bytes = text.as_bytes();
    let mut i = bytes.len();
    let mut words = 0usize;
    let mut in_word = false;
    while i > 0 {
        i -= 1;
        let is_ws = bytes[i].is_ascii_whitespace();
        if !is_ws && !in_word {
            in_word = true;
            words += 1;
            if words > n {
                i += 1;
                break;
            }
        } else if is_ws && in_word {
            in_word = false;
        }
    }
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    &text[i..]
}

/// Symmetric to `clip_prefix_words`: keep the first `n` words, walking left-to-right.
fn clip_suffix_words(text: &str, n: usize) -> &str {
    if n == 0 || text.is_empty() {
        return text;
    }
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut words = 0usize;
    let mut in_word = false;
    while i < bytes.len() {
        let is_ws = bytes[i].is_ascii_whitespace();
        if !is_ws && !in_word {
            in_word = true;
            words += 1;
            if words > n {
                break;
            }
        } else if is_ws && in_word {
            in_word = false;
        }
        i += 1;
    }
    while i < bytes.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    &text[..i]
}
