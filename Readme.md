# Directory Spider Rust

## Usage

```bash
Usage: DirectorySpider.exe [OPTIONS]

Options:
  -h, --help  Print help (see more with '--help')

Files in output:
  -d, --directory-path <DIRECTORY_PATH>  Root directory. Repeat `-d` for multiple roots
  -L, --input-list <INPUT_LIST>          File of newline-separated roots (# and blank lines ignored)
  -i, --include <INCLUDE>                Include only these extensions (comma-separated)
  -e, --exclude <EXCLUDE>                Exclude these extensions (comma-separated)
  -f, --follow-lnk                       Follow .lnk shortcuts to their targets

Content scan scope:
  -k, --keyword-include <KEYWORD_INCLUDE>
          Extensions to scan for keywords (subset of -i). Takes EXTENSIONS, not search terms
      --keyword-exclude <KEYWORD_EXCLUDE>
          Extensions never scanned (wins over -k)
      --max-scan-size <MAX_SCAN_SIZE>
          Max file size (bytes) scanned for keywords [default: 10485760]

Scan execution:
      --threads <THREADS>
          Number of worker threads for metadata and content scanning (1 = single-threaded) [default: 1]
  -q, --quiet
          Suppress non-fatal scan diagnostics. Progress output is still shown

Search terms:
      --keywords <KEYWORDS>            Literal search terms (comma-separated). THIS is the keyword flag
      --keywords-file <KEYWORDS_FILE>  File of newline-separated literal keywords (# and blank lines ignored)
      --keyword-regex <KEYWORD_REGEX>  Regex pattern to search for. Repeat flag for multiple patterns
      --case-sensitive                 Case-sensitive keyword/regex matching

Match output:
      --matches-only
          Only emit files that had at least one keyword/regex hit
      --context-lines <CONTEXT_LINES>
          Lines of context above and below each match (0 = matched line only) [default: 1]
      --context-words <CONTEXT_WORDS>
          Words of context on the matched line, before and after the match (0 = full same-line prefix/suffix, no word clipping) [default: 8]
      --max-matches-per-file <MAX_MATCHES_PER_FILE>
          Cap on MatchHits emitted per file (0 = unlimited). `matched_keywords` still lists every distinct hit [default: 100]
      --max-context-line-chars <MAX_CONTEXT_LINE_CHARS>
          Max characters per emitted context line/segment, not total before/after field size (0 = unlimited) [default: 0]
      --hash-context-lines
          Replace repeated match context text with compact hashes and write --context-index-path at the end
      --live-context-index
          Update --context-index-path during the scan instead of only at the end

Output:
  -o, --output-path <OUTPUT_PATH>  Output JSON file [default: metadata.json]
      --context-index-path <CONTEXT_INDEX_PATH>
          Output path for the sidecar context hash index written by --hash-context-lines
      --flush-every <FLUSH_EVERY>  Flush output to disk every N entries (0 = only at end) [default: 100]

Note: `-k` takes EXTENSIONS, not keywords. Search terms go in `--keywords`.

Examples:
  jinx.exe -d C:\Users -i txt,log --keywords password,secret
  jinx.exe -d \\fs01\share -i docx,xlsx -o share.json
  jinx.exe -L roots.txt --keyword-regex "AKIA[0-9A-Z]{16}"
  jinx.exe -d C:\Logs -i txt,log --keywords password --matches-only
  jinx.exe -d C:\Logs -i txt,log --keywords password --matches-only --hash-context-lines
  jinx.exe -d C:\Logs -i txt,log --keywords password --matches-only --threads 4
  jinx.exe -d C:\Users -q
```

### Progress and quiet diagnostics

DirectorySpider prints the immediate child directory currently being scanned,
for example `[*] Scanning top-level directory: C:\Users\Alice`. Use `-q` /
`--quiet` to suppress non-fatal diagnostics such as access denied, metadata
read failures, oversized-file scan skips, and shortcut parse warnings. Progress
and fatal errors are still printed.

### Context hash index

Use `--hash-context-lines` when match outputs get too large because many matches
repeat the same `before` / `after` context. It works with or without
`--matches-only`; only emitted `matches[]` entries change. The main output then
contains `before_hash` and `after_hash` fields instead of the full context text.
The sidecar index maps each hash back to the original value:

```json
{
  "algorithm": "blake3-128-base64url-no-pad",
  "values": {
    "b3:7Jf4nqZK9vX0lL2mQ8pTaw": "full context text"
  }
}
```

If `--context-index-path` is omitted, the sidecar path is derived from the output
path, for example `metadata.json` writes `metadata.context-index.json`. The
sidecar is written after the main JSON output is closed. Valid zero-match
hash-mode scans leave an empty sidecar index.

Use `--live-context-index` when crash recovery or tail-readers must decode
hashed entries during the scan. Live mode initializes the sidecar at scan start
and rewrites a full JSON snapshot whenever a new context value is indexed,
before emitting entries that reference it. This creates more write traffic than
the main output's `--flush-every` cadence and is more sensitive to Windows/SMB
file replacement failures.

### Keyword list

```
# Generic secrets (substring + case-insensitive, so passw covers password/passwd/Passw0rd)
passw
pwd
pass=
pass:
secret
token
bearer
apikey
api_key
api-key
authorization
credential
connectionstring
conn_str

# Keys
private_key
privatekey
PRIVATE KEY
PuTTY-User-Key
ssh-rsa

# Cloud / SaaS token prefixes
AKIA
xoxb-
xoxp-
ghp_
ghs_
gho_
sk_live_

# Windows-specific
AutoAdminLogon
```

### Command for share enum

```bash
DirectorySpider.exe -L share_list.txt -i txt,log,md,csv,tsv,rtf,ini,cfg,conf,config,xml,yaml,yml,toml,properties,env,json,ps1,psm1,psd1,bat,cmd,sh,bash,zsh,vbs,js,reg,sql,py,rb,php,pl,java,cs,go,rs,ts,bak,old,backup,orig,tmp,docx,xlsx,pptx,pdf --keywords-file keywords.txt --matches-only --context-lines 5 --context-words 0 --max-context-line-chars 500 --hash-context-lines
```

## Remarks

* By default this compiles static
* Do not include dots in extensions
