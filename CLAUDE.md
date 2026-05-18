# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Rust implementation of a Windows directory scanner. Walks one or more roots, emits a streaming JSON array of file metadata, and optionally scans file contents for literal keywords and regex patterns. Sibling implementations in PowerShell and C# live in the parent repo; this directory is the Rust crate.

## Platform

**Windows-only build target.** `src/metadata.rs` uses `std::os::windows::fs::MetadataExt::file_size()` and the `parselnk` crate to resolve `.lnk` shortcuts. `build.rs` invokes `static_vcruntime::metabuild()` to statically link the MSVC C runtime.

On Linux, plain `cargo build` will fail with `no method named file_size` and `could not find windows in os`. Cross-compile instead:

```bash
cargo build --target x86_64-pc-windows-gnu
```

The resulting `.exe` runs under wine for local testing. When invoking via wine, pass Windows-style paths (e.g. `Z:\tmp\scan`, since wine maps `/` to `Z:\`).

On Windows host:

```powershell
cargo build --release
# binary: ./target/release/DirectorySpider.exe
```

Unit tests live in `src/` and should be run for the Windows target:

```bash
cargo test --target x86_64-pc-windows-gnu
```

## CLI shape

Flags group into three categories (also printed in `--help`):

- **files in output**: `-d` (root, repeatable), `-L` (file of newline-separated roots), `-i`/`-e` (include/exclude extensions)
- **content scan scope**: `-k`/`--keyword-include` (extensions eligible for content scan — *takes extensions, not search terms*), `--keyword-exclude`, `--max-scan-size`
- **search terms**: `--keywords` (comma-separated literals), `--keywords-file` (newline-separated literals from file), `--keyword-regex` (repeat flag for multiple patterns), `--case-sensitive`
- **match output**: `--matches-only`, `--context-lines`, `--context-words`, `--max-matches-per-file`, `--max-context-line-chars` (0 = unlimited)

The most common confusion: `-k` looks like it should take keywords but takes *extensions*. Search terms go in `--keywords` / `--keywords-file` / `--keyword-regex`.

`-L` and `--keywords-file` both use the same file format: newline-separated entries, blank lines and lines starting with `#` ignored, trimmed. They merge with their CLI counterparts (`-d`, `--keywords`) and dedupe while preserving first-seen order. The helpers `collect_roots` and `collect_keywords` in `src/main.rs` mirror each other — when adding another file-input flag, copy this pattern.

## Architecture

**Streaming JSON output.** `walk_path` in `src/main.rs` writes the output array by hand: opens with `[`, writes each entry via `serde_json::to_writer` separated by commas (tracked through `first_entry: &mut bool`), and closes with `]`. A `BufWriter` is flushed every `--flush-every` entries (default 100) so the file grows on disk during long scans and watchers/tail can see progress. The final `]` write and flush are propagated to `main` so a successful exit only happens when the file is closed cleanly.

**Walker.** BFS over roots using a `VecDeque<PathBuf>` queue plus a `visited_base_paths: HashSet<PathBuf>` set. Each root is expanded with `walkdir::WalkDir` filtered to files; the `visited_base_paths` check prevents re-walking when `.lnk` resolution adds a directory back into the queue.

**`.lnk` following.** When `--follow-lnk` is on, encountering a `.lnk` file resolves the target with `parselnk::Lnk`. If the target is a file *outside* every existing root, its metadata is emitted in place; if it's a directory outside every existing root, it is pushed onto the BFS queue. The "outside every root" check (`!roots.iter().any(|b| target.starts_with(b))`) is what prevents double-emitting files that the walker would have hit anyway.

**Keyword scanner (`src/scanner.rs`).** `KeywordScanner` is built once from `Args` and consulted per file. `applies_to(ext)` gates extension scope (`--keyword-include` / `--keyword-exclude`); `scan(path, size)` reads the file, decodes as `String::from_utf8_lossy`, and runs all literals + regexes, returning a deduped `Vec<String>` of matched needles. Two non-obvious details:

- For case-insensitive matching (the default), `literals_lc` is precomputed once and `content.to_lowercase()` runs per file — avoid recomputing the lowercase keyword list per scan.
- Regex case-insensitivity is implemented by prepending `(?i)` to each pattern before compilation, not via `RegexBuilder`. `--case-sensitive` flips both branches consistently.
- `--max-context-line-chars` is an opt-in cap for each emitted `before` / `after` context line or same-line segment. It keeps the text nearest the match and leaves the `match` field untouched.

**Safety on missing roots.** `walk_path` validates roots *before* creating the output file. If every root is missing, it returns without truncating any existing output. This avoids the silent-overwrite-to-`[]` footgun on path typos.

**Per-entry errors are non-fatal.** Errors reading metadata, scanning a file, or writing one entry are logged to stderr with a `[!]` prefix and the scan continues. Only the final flush failure can cause a non-zero exit (code 3); empty results cause exit 1.

## Output schema

Each entry is a `FileMetadata` (`src/metadata.rs`): `name`, `full_path`, `extension`, `size`, `creation_time`, `last_access`, `last_write`, `is_read_only`, `matched_keywords`. Timestamps are formatted as `"/Date(<unix-ms>)/"` (the .NET JSON date convention) by `helper::format_system_time` — preserved across implementations for cross-compatibility with the PowerShell/C# versions.
