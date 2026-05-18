use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::{Regex, RegexBuilder};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::metadata::MatchHit;
use crate::Args;

pub struct ScanResult {
    pub keywords: Vec<String>,
    pub matches: Vec<MatchHit>,
}

pub struct KeywordScanner {
    literal_keywords: Vec<String>,
    literal_matcher: Option<AhoCorasick>,
    regexes: Vec<(String, Regex)>,
    include_exts: Vec<String>,
    exclude_exts: Vec<String>,
    max_scan_size: u64,
    enabled: bool,
    context_lines: usize,
    context_words: usize,
    max_matches: usize,
    max_context_line_chars: usize,
}

impl KeywordScanner {
    pub fn new(args: &Args) -> Result<Self, String> {
        let mut literal_keywords = Vec::new();
        let mut literal_matcher = None;
        let mut regexes: Vec<(String, Regex)> =
            Vec::with_capacity(args.keywords.len() + args.keyword_regex.len());

        let literals_can_use_aho = args
            .keywords
            .iter()
            .all(|needle| !needle.is_empty() && (args.case_sensitive || needle.is_ascii()));

        if literals_can_use_aho {
            literal_keywords = args.keywords.clone();
            if !literal_keywords.is_empty() {
                literal_matcher = Some(
                    AhoCorasickBuilder::new()
                        .ascii_case_insensitive(!args.case_sensitive)
                        .build(&literal_keywords)
                        .map_err(|err| err.to_string())?,
                );
            }
        } else {
            for needle in &args.keywords {
                let pattern = regex::escape(needle);
                let regex = RegexBuilder::new(&pattern)
                    .case_insensitive(!args.case_sensitive)
                    .build()
                    .map_err(|err| err.to_string())?;
                regexes.push((needle.clone(), regex));
            }
        }

        for pat in &args.keyword_regex {
            let effective = if args.case_sensitive {
                pat.clone()
            } else {
                format!("(?i){}", pat)
            };
            regexes.push((
                pat.clone(),
                Regex::new(&effective).map_err(|err| err.to_string())?,
            ));
        }

        let enabled = literal_matcher.is_some() || !regexes.is_empty();

        Ok(KeywordScanner {
            literal_keywords,
            literal_matcher,
            regexes,
            include_exts: args.keyword_include.clone(),
            exclude_exts: args.keyword_exclude.clone(),
            max_scan_size: args.max_scan_size,
            enabled,
            context_lines: args.context_lines,
            context_words: args.context_words,
            max_matches: args.max_matches_per_file,
            max_context_line_chars: args.max_context_line_chars,
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
            return ScanResult {
                keywords: Vec::new(),
                matches: Vec::new(),
            };
        }

        if file_size > self.max_scan_size {
            eprintln!(
                "[*] Skipping scan, file exceeds --max-scan-size ({} > {}): {}",
                file_size,
                self.max_scan_size,
                path.display()
            );
            return ScanResult {
                keywords: Vec::new(),
                matches: Vec::new(),
            };
        }

        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("[!] scan read {}: {}", path.display(), err);
                return ScanResult {
                    keywords: Vec::new(),
                    matches: Vec::new(),
                };
            }
        };

        let content = String::from_utf8_lossy(&bytes);
        let mut keywords: Vec<String> = Vec::new();
        let mut seen_keywords: HashSet<String> = HashSet::new();
        let mut matches: Vec<MatchHit> = Vec::new();
        let cap_unlimited = self.max_matches == 0;
        let mut line_starts = LazyLineStarts::new();

        if let Some(literal_matcher) = &self.literal_matcher {
            let mut seen_literals = vec![false; self.literal_keywords.len()];
            let mut literal_positions = vec![Vec::new(); self.literal_keywords.len()];
            let mut literal_last_end = vec![0usize; self.literal_keywords.len()];

            for m in literal_matcher.find_overlapping_iter(content.as_ref()) {
                let pattern_idx = m.pattern().as_usize();
                if m.start() < literal_last_end[pattern_idx] {
                    continue;
                }
                literal_last_end[pattern_idx] = m.end();
                seen_literals[pattern_idx] = true;
                if cap_unlimited || literal_positions[pattern_idx].len() < self.max_matches {
                    literal_positions[pattern_idx].push((m.start(), m.end()));
                }
            }

            for (idx, display) in self.literal_keywords.iter().enumerate() {
                if seen_literals[idx] && seen_keywords.insert(display.clone()) {
                    keywords.push(display.clone());
                }

                for (start, end) in &literal_positions[idx] {
                    if cap_unlimited || matches.len() < self.max_matches {
                        matches.push(build_hit(
                            &content,
                            line_starts.get(&content),
                            *start,
                            *end,
                            display,
                            self.context_lines,
                            self.context_words,
                            self.max_context_line_chars,
                        ));
                    } else {
                        break;
                    }
                }
            }
        }

        for (display, regex) in &self.regexes {
            if !cap_unlimited && matches.len() >= self.max_matches {
                if regex.is_match(&content) && seen_keywords.insert(display.clone()) {
                    keywords.push(display.clone());
                }
                continue;
            }

            for m in regex.find_iter(&content) {
                if seen_keywords.insert(display.clone()) {
                    keywords.push(display.clone());
                }
                if cap_unlimited || matches.len() < self.max_matches {
                    matches.push(build_hit(
                        &content,
                        line_starts.get(&content),
                        m.start(),
                        m.end(),
                        display,
                        self.context_lines,
                        self.context_words,
                        self.max_context_line_chars,
                    ));
                } else {
                    break;
                }
            }
        }

        ScanResult { keywords, matches }
    }
}

#[derive(Default)]
struct LazyLineStarts {
    starts: Option<Vec<usize>>,
}

impl LazyLineStarts {
    fn new() -> Self {
        Self::default()
    }

    fn get<'a>(&'a mut self, content: &str) -> &'a [usize] {
        if self.starts.is_none() {
            self.starts = Some(compute_line_starts(content));
        }
        self.starts.as_deref().expect("line starts initialized")
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
    max_context_line_chars: usize,
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

    let before = clip_context_keep_end(above_portion, clipped_prefix, max_context_line_chars);
    let after = clip_context_keep_start(clipped_suffix, below_portion, max_context_line_chars);

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
        before_hash: None,
        after_hash: None,
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

fn clip_context_keep_end(
    line_context: &str,
    match_line_context: &str,
    max_context_line_chars: usize,
) -> String {
    let mut out = String::with_capacity(line_context.len() + match_line_context.len());
    push_clipped_lines(
        line_context,
        max_context_line_chars,
        ClipSide::End,
        &mut out,
    );
    out.push_str(clip_chars_from_end(
        match_line_context,
        max_context_line_chars,
    ));
    out
}

fn clip_context_keep_start(
    match_line_context: &str,
    line_context: &str,
    max_context_line_chars: usize,
) -> String {
    let mut out = String::with_capacity(match_line_context.len() + line_context.len());
    out.push_str(clip_chars_from_start(
        match_line_context,
        max_context_line_chars,
    ));
    push_clipped_lines(
        line_context,
        max_context_line_chars,
        ClipSide::Start,
        &mut out,
    );
    out
}

#[derive(Clone, Copy)]
enum ClipSide {
    Start,
    End,
}

fn push_clipped_lines(text: &str, max_context_line_chars: usize, side: ClipSide, out: &mut String) {
    for line in text.split_inclusive('\n') {
        let (content, newline) = split_line_ending(line);
        let clipped = match side {
            ClipSide::Start => clip_chars_from_start(content, max_context_line_chars),
            ClipSide::End => clip_chars_from_end(content, max_context_line_chars),
        };
        out.push_str(clipped);
        out.push_str(newline);
    }
}

fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(content) = line.strip_suffix("\r\n") {
        (content, "\r\n")
    } else if let Some(content) = line.strip_suffix('\n') {
        (content, "\n")
    } else {
        (line, "")
    }
}

fn clip_chars_from_start(text: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return text;
    }
    match text.char_indices().nth(max_chars) {
        Some((idx, _)) => &text[..idx],
        None => text,
    }
}

fn clip_chars_from_end(text: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return text;
    }
    // nth(max_chars) lands one character before the kept suffix boundary.
    match text.char_indices().rev().nth(max_chars) {
        Some((idx, ch)) => &text[idx + ch.len_utf8()..],
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use super::{build_hit, compute_line_starts, KeywordScanner};
    use crate::Args;
    use clap::Parser;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("directory-spider-scanner-{}-{}", name, suffix))
    }

    fn scanner_from_args(args: &[&str]) -> KeywordScanner {
        let args = Args::try_parse_from(args).expect("arguments parse");
        KeywordScanner::new(&args).expect("scanner builds")
    }

    fn scan_fixture(
        name: &str,
        content: &str,
        scanner: &KeywordScanner,
    ) -> crate::scanner::ScanResult {
        let root = unique_temp_dir(name);
        fs::create_dir_all(&root).expect("create fixture directory");
        let path = root.join("fixture.txt");
        fs::write(&path, content).expect("write fixture");
        let result = scanner.scan(&path, content.len() as u64);
        fs::remove_dir_all(root).expect("remove fixture directory");
        result
    }

    fn hit_for_options(
        content: &str,
        needle: &str,
        context_lines: usize,
        context_words: usize,
        max_context_line_chars: usize,
    ) -> crate::metadata::MatchHit {
        let starts = compute_line_starts(content);
        let start = content.find(needle).expect("needle present");
        build_hit(
            content,
            &starts,
            start,
            start + needle.len(),
            needle,
            context_lines,
            context_words,
            max_context_line_chars,
        )
    }

    fn hit_for(
        content: &str,
        needle: &str,
        max_context_line_chars: usize,
    ) -> crate::metadata::MatchHit {
        hit_for_options(content, needle, 1, 0, max_context_line_chars)
    }

    #[test]
    fn literal_scan_reports_all_keywords_after_match_cap_is_full() {
        let scanner = scanner_from_args(&[
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "alpha,beta,gamma",
            "--max-matches-per-file",
            "1",
        ]);

        let result = scan_fixture("literal-cap-keywords", "alpha beta gamma", &scanner);

        assert_eq!(result.keywords, vec!["alpha", "beta", "gamma"]);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].keyword, "alpha");
        assert_eq!(result.matches[0].r#match, "alpha");
    }

    #[test]
    fn literal_scan_keeps_non_overlapping_matches_for_same_keyword() {
        let scanner = scanner_from_args(&[
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "aa",
            "--case-sensitive",
        ]);

        let result = scan_fixture("literal-non-overlap", "aaaa", &scanner);

        assert_eq!(result.keywords, vec!["aa"]);
        assert_eq!(result.matches.len(), 2);
        assert_eq!(result.matches[0].column, 1);
        assert_eq!(result.matches[1].column, 3);
    }

    #[test]
    fn literal_scan_preserves_cross_keyword_overlap() {
        let scanner = scanner_from_args(&[
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "dog,doghouse",
            "--case-sensitive",
        ]);

        let result = scan_fixture("literal-cross-overlap", "doghouse", &scanner);

        assert_eq!(result.keywords, vec!["dog", "doghouse"]);
        assert_eq!(result.matches.len(), 2);
        assert_eq!(result.matches[0].keyword, "dog");
        assert_eq!(result.matches[1].keyword, "doghouse");
    }

    #[test]
    fn literal_scan_keeps_existing_case_insensitive_context_shape() {
        let scanner = scanner_from_args(&[
            "DirectorySpider",
            "-d",
            "C:\\Logs",
            "--keywords",
            "secret,token",
            "--context-lines",
            "1",
            "--context-words",
            "0",
            "--max-context-line-chars",
            "20",
        ]);

        let result = scan_fixture(
            "literal-context-shape",
            "above line\nprefix SECRET suffix\nbelow line\n",
            &scanner,
        );

        assert_eq!(result.keywords, vec!["secret"]);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].keyword, "secret");
        assert_eq!(result.matches[0].line, 2);
        assert_eq!(result.matches[0].column, 8);
        assert_eq!(result.matches[0].before, "above line\nprefix ");
        assert_eq!(result.matches[0].r#match, "SECRET");
        assert_eq!(result.matches[0].after, " suffix\nbelow line\n");
    }

    #[test]
    fn zero_context_line_cap_preserves_full_context() {
        let hit = hit_for(
            "above one long\nprefix secret suffix\nbelow one long\n",
            "secret",
            0,
        );

        assert_eq!(hit.before, "above one long\nprefix ");
        assert_eq!(hit.r#match, "secret");
        assert_eq!(hit.after, " suffix\nbelow one long\n");
    }

    #[test]
    fn before_context_keeps_text_nearest_the_match() {
        let hit = hit_for("0123456789ABCDEF\npre secret post\n", "secret", 5);

        assert_eq!(hit.before, "BCDEF\npre ");
    }

    #[test]
    fn after_context_keeps_text_nearest_the_match() {
        let hit = hit_for("pre secret post\n0123456789ABCDEF\n", "secret", 5);

        assert_eq!(hit.after, " post\n01234\n");
    }

    #[test]
    fn same_line_prefix_and_suffix_are_capped() {
        let hit = hit_for("0123456789secretABCDEFGHIJ", "secret", 4);

        assert_eq!(hit.before, "6789");
        assert_eq!(hit.after, "ABCD");
    }

    #[test]
    fn unicode_context_clips_on_character_boundaries() {
        let hit = hit_for("áéíóúsecretßçđ", "secret", 3);

        assert_eq!(hit.before, "íóú");
        assert_eq!(hit.after, "ßçđ");
    }

    #[test]
    fn crlf_line_endings_are_preserved_outside_the_character_cap() {
        let hit = hit_for("0123456789ABCDEF\r\npre secret post\r\n", "secret", 4);

        assert_eq!(hit.before, "CDEF\r\npre ");
    }

    #[test]
    fn each_context_line_is_clipped_independently() {
        let hit = hit_for_options(
            "above-one\nabove-two\npre secret post\nbelow-one\nbelow-two\n",
            "secret",
            2,
            0,
            3,
        );

        assert_eq!(hit.before, "one\ntwo\nre ");
        assert_eq!(hit.after, " po\nbel\nbel\n");
    }

    #[test]
    fn word_context_is_clipped_before_character_cap() {
        let hit = hit_for_options(
            "alpha beta gamma delta secret epsilon zeta eta theta",
            "secret",
            0,
            2,
            6,
        );

        assert_eq!(hit.before, "delta ");
        assert_eq!(hit.after, " epsil");
    }

    #[test]
    fn character_cap_does_not_truncate_match_text() {
        let hit = hit_for("xx SECRET-LONG yy", "SECRET-LONG", 2);

        assert_eq!(hit.before, "x ");
        assert_eq!(hit.r#match, "SECRET-LONG");
        assert_eq!(hit.after, " y");
    }
}
