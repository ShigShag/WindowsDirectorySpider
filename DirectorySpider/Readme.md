# Directory Spider Rust

## Prerequisites

Install Rust for [Windows](https://www.rust-lang.org/learn/get-started)

## Run

```powershell
// Compile
PS > cargo build --release

// Binary will be stored in ./target/release/DirectorySpider.exe
PS > ./target/release/DirectorySpider.exe --help
Command line argument parser
```

```bash
Usage: DirectorySpider.exe [OPTIONS]

Options:
  -d, --directory-path <DIRECTORY_PATH>
          Root directory. Repeat `-d` for multiple roots
  -L, --input-list <INPUT_LIST>
          File of newline-separated roots (# and blank lines ignored)
  -o, --output-path <OUTPUT_PATH>
          Output JSON file [default: metadata.json]
  -i, --include <INCLUDE>
          Include only these extensions (comma-separated)
  -e, --exclude <EXCLUDE>
          Exclude these extensions (comma-separated)
  -f, --follow-lnk
          Follow .lnk shortcuts to their targets
  -k, --keyword-include <KEYWORD_INCLUDE>
          Extensions to scan for keywords (subset of -i). Takes EXTENSIONS, not search terms
      --keyword-exclude <KEYWORD_EXCLUDE>
          Extensions never scanned (wins over -k)
      --keywords <KEYWORDS>
          Literal search terms (comma-separated). THIS is the keyword flag
      --keyword-regex <KEYWORD_REGEX>
          Regex pattern to search for. Repeat flag for multiple patterns
      --case-sensitive
          Case-sensitive keyword/regex matching
      --max-scan-size <MAX_SCAN_SIZE>
          Max file size (bytes) scanned for keywords [default: 10485760]
  -h, --help
          Print help (see more with '--help')

Flags fall in 3 groups:
  files in output    -d  -L  -i  -e
  content scan       -k  --keyword-exclude  --max-scan-size
  search terms       --keywords  --keyword-regex  --case-sensitive

`-k` takes EXTENSIONS, not keywords. Search terms go in `--keywords`.

Examples:
   DirectorySpider.exe -d C:\Users -i txt,log --keywords password,secret
   DirectorySpider.exe -d \\fs01\share -i docx,xlsx -o share.json
   DirectorySpider.exe -L roots.txt --keyword-regex "AKIA[0-9A-Z]{16}"

Run `--help` for full docs and more examples.
```

### More help

```bash
Usage: DirectorySpider.exe [OPTIONS]

Options:
  -d, --directory-path <DIRECTORY_PATH>
          Root directory. Repeat `-d` for multiple roots

  -L, --input-list <INPUT_LIST>
          File of newline-separated roots (# and blank lines ignored)

  -o, --output-path <OUTPUT_PATH>
          Output JSON file

          [default: metadata.json]

  -i, --include <INCLUDE>
          Include only these extensions (comma-separated)

  -e, --exclude <EXCLUDE>
          Exclude these extensions (comma-separated)

  -f, --follow-lnk
          Follow .lnk shortcuts to their targets

  -k, --keyword-include <KEYWORD_INCLUDE>
          Extensions eligible for content scan, comma-separated.
          Must be a subset of --include. Empty = scan all in-scope files.
          Takes EXTENSIONS, not keywords. Search terms go in --keywords.
          Example: -i txt,log -k txt --keywords password

      --keyword-exclude <KEYWORD_EXCLUDE>
          Extensions never scanned (wins over -k)

      --keywords <KEYWORDS>
          Literal search terms (comma-separated). THIS is the keyword flag

      --keyword-regex <KEYWORD_REGEX>
          Regex pattern to search for in file contents. Repeat flag for multiple patterns.

          Rust `regex` crate syntax (PCRE-like, no lookaround/backrefs).
          Case-insensitive by default; --case-sensitive overrides.
          One pattern per flag (no comma splitting), so quantifiers like `{1,3}` work.

          Examples:
            --keyword-regex "v\d+\.\d+"               version strings
            --keyword-regex "[\w.+-]+@[\w.-]+"         email addresses
            --keyword-regex "\d{1,3}(\.\d{1,3}){3}"   IPv4 addresses
            --keyword-regex "TODO|FIXME|HACK"            any of three tokens


      --case-sensitive
          Case-sensitive keyword/regex matching

      --max-scan-size <MAX_SCAN_SIZE>
          Max file size (bytes) scanned for keywords

          [default: 10485760]

  -h, --help
          Print help (see a summary with '-h')

EXAMPLES

Metadata only:
   DirectorySpider.exe -d C:\Users\Public
   DirectorySpider.exe -d C:\Users -d D:\Data -o out.json
   DirectorySpider.exe -L roots.txt -i exe,dll -e iso

Literal keyword scan (search terms = --keywords, scope = -k/-i):
   DirectorySpider.exe -d C:\Logs -i txt,log --keywords password,secret,api_key
   DirectorySpider.exe -d C:\src --keywords TODO,FIXME --case-sensitive

Regex scan:
   DirectorySpider.exe -d C:\Users -i txt,csv,log \
      --keyword-regex "[\w.+-]+@[\w.-]+" \
      --keyword-regex "\d{1,3}(\.\d{1,3}){3}"

Combine + exclude binaries from scan, cap size at 1 MiB:
   DirectorySpider.exe -d C:\Projects -i txt,md,rs,log \
      --keyword-exclude exe,dll \
      --keywords password,token \
      --keyword-regex "AKIA[0-9A-Z]{16}" \
      --max-scan-size 1048576

SMB shares (PowerShell, UNC unquoted unless path has spaces):
  PS> .\ DirectorySpider.exe -d \\fs01\share -o share.json
  PS> .\ DirectorySpider.exe -d '\\fs01\HR Files' -i docx,xlsx -o hr.json
  PS> .\ DirectorySpider.exe `
          -d \\dc01\NETLOGON `
          -d \\fs01\IT\scripts `
          -i ps1,bat,ini,xml `
          --keywords password,Passw0rd `
          -o creds.json

Follow .lnk shortcuts (may jump to SMB / off-tree targets):
   DirectorySpider.exe -d C:\Users\Public\Desktop -f
```

## Remarks

* By default this compiles static
* Do not include dots in extensions
