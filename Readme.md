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

Output:
  -o, --output-path <OUTPUT_PATH>  Output JSON file [default: metadata.json]
      --flush-every <FLUSH_EVERY>  Flush output to disk every N entries (0 = only at end) [default: 100]

Note: `-k` takes EXTENSIONS, not keywords. Search terms go in `--keywords`.

Examples:
  jinx.exe -d C:\Users -i txt,log --keywords password,secret
  jinx.exe -d \\fs01\share -i docx,xlsx -o share.json
  jinx.exe -L roots.txt --keyword-regex "AKIA[0-9A-Z]{16}"
  jinx.exe -d C:\Logs -i txt,log --keywords password --matches-only
```
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
DirectorySpider.exe -L share_list.txt -i txt,log,md,csv,tsv,rtf,ini,cfg,conf,config,xml,yaml,yml,toml,properties,env,json,ps1,psm1,psd1,bat,cmd,sh,bash,zsh,vbs,js,reg,sql,py,rb,php,pl,java,cs,go,rs,ts,bak,old,backup,orig,tmp,docx,xlsx,pptx,pdf --keywords-file keywords.txt --matches-only --context-lines 5 --context-words 0
```

## Remarks

* By default this compiles static
* Do not include dots in extensions
