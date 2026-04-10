package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/momenbasel/liffier/internal/encoding"
	"github.com/momenbasel/liffier/internal/fuzzer"
	"github.com/momenbasel/liffier/internal/output"
)

const version = "2.0.0"

func usage() {
	fmt.Fprintf(os.Stderr, `liffier v%s - Path traversal / LFI fuzzer

USAGE:
  liffier fuzz   <url> [options]        Fuzz a URL for path traversal
  liffier scan   <url> [options]        Quick scan with multiple common files
  liffier payloads [options]            Generate payloads to stdout
  liffier encodings                     List all encoding techniques
  liffier version                       Print version

FUZZ OPTIONS:
  -f, --file <path>        Target file (default: /etc/passwd)
  -l, --list <file>        Wordlist of target files (one per line)
  -d, --depth <n>          Max traversal depth (default: 10)
  -e, --encoding <name>    Use specific encoding (repeatable)
  -b, --bypass             Enable null-byte/extension bypass suffixes
  -w, --workers <n>        Concurrent goroutines (default: 10, no upper limit)
  -t, --timeout <s>        Per-request timeout in seconds (default: 10)
  --delay <ms>             Delay between requests in ms (default: 0)
  -x, --proxy <url>        HTTP proxy (e.g. http://127.0.0.1:8080)
  -c, --cookie <str>       Cookies (key=val; key2=val2)
  -H, --header <K:V>       Extra header (repeatable)
  -m, --method <verb>      HTTP method (default: GET)
  -L, --follow             Follow redirects
  -o, --output <file>      Save results to file
  --format <fmt>           Output format: json, jsonl, csv (default: json)
  --hits-only              Only show/export hits
  -q, --quiet              Minimal output
  --no-color               Disable colors

SCAN OPTIONS:
  Same as fuzz, but -f adds to the default file list instead of replacing it.

EXAMPLES:
  liffier fuzz "https://target.com/page?file="
  liffier fuzz "https://target.com/page?file=" -f /etc/shadow -w 100 -x http://127.0.0.1:8080
  liffier fuzz "https://target.com/page?file=" -l files.txt -b -w 200
  liffier scan "https://target.com/page?file=" --bypass
  liffier payloads -f /etc/passwd --bypass | ffuf -u "https://target/file=FUZZ" -w -
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "fuzz":
		cmdFuzz(args)
	case "scan":
		cmdScan(args)
	case "payloads":
		cmdPayloads(args)
	case "encodings":
		cmdEncodings()
	case "version":
		fmt.Printf("liffier v%s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

type cliFlags struct {
	url        string
	file       string
	list       string
	depth      int
	encodings  []string
	bypass     bool
	workers    int
	timeout    int
	delay      int
	proxy      string
	cookie     string
	headers    map[string]string
	method     string
	follow     bool
	output     string
	format     string
	hitsOnly   bool
	quiet      bool
	noColor    bool
	extraFiles []string
}

func parseFlags(args []string) cliFlags {
	f := cliFlags{
		depth:   10,
		workers: 10,
		timeout: 10,
		method:  "GET",
		format:  "json",
		file:    "/etc/passwd",
		headers: make(map[string]string),
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() string {
			i++
			if i < len(args) {
				return args[i]
			}
			fmt.Fprintf(os.Stderr, "Missing value for %s\n", arg)
			os.Exit(1)
			return ""
		}

		switch arg {
		case "-f", "--file":
			f.file = next()
		case "-l", "--list":
			f.list = next()
		case "-d", "--depth":
			fmt.Sscanf(next(), "%d", &f.depth)
		case "-e", "--encoding":
			f.encodings = append(f.encodings, next())
		case "-b", "--bypass":
			f.bypass = true
		case "-w", "--workers":
			fmt.Sscanf(next(), "%d", &f.workers)
		case "-t", "--timeout":
			fmt.Sscanf(next(), "%d", &f.timeout)
		case "--delay":
			fmt.Sscanf(next(), "%d", &f.delay)
		case "-x", "--proxy":
			f.proxy = next()
		case "-c", "--cookie":
			f.cookie = next()
		case "-H", "--header":
			h := next()
			if idx := strings.Index(h, ":"); idx > 0 {
				f.headers[strings.TrimSpace(h[:idx])] = strings.TrimSpace(h[idx+1:])
			}
		case "-m", "--method":
			f.method = strings.ToUpper(next())
		case "-L", "--follow":
			f.follow = true
		case "-o", "--output":
			f.output = next()
		case "--format":
			f.format = next()
		case "--hits-only":
			f.hitsOnly = true
		case "-q", "--quiet":
			f.quiet = true
		case "--no-color":
			f.noColor = true
		default:
			if !strings.HasPrefix(arg, "-") && f.url == "" {
				f.url = arg
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", arg)
			}
		}
	}
	return f
}

// Color helpers
func green(s string) string  { return "\033[32m" + s + "\033[0m" }
func red(s string) string    { return "\033[31m" + s + "\033[0m" }
func yellow(s string) string { return "\033[33m" + s + "\033[0m" }
func cyan(s string) string   { return "\033[36m" + s + "\033[0m" }
func dim(s string) string    { return "\033[2m" + s + "\033[0m" }
func bold(s string) string   { return "\033[1m" + s + "\033[0m" }

func cmdFuzz(args []string) {
	f := parseFlags(args)
	if f.url == "" {
		fmt.Fprintln(os.Stderr, "Error: URL required")
		os.Exit(1)
	}

	// Collect target files
	targetFiles := []string{f.file}
	if f.list != "" {
		lines, err := encoding.LoadWordlist(f.list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading wordlist: %v\n", err)
			os.Exit(1)
		}
		targetFiles = lines
	}

	var allResults []fuzzer.Result
	var totalHits int

	for _, targetFile := range targetFiles {
		cfg := fuzzer.Config{
			URL:             f.url,
			TargetFile:      targetFile,
			MaxDepth:        f.depth,
			Encodings:       f.encodings,
			BypassSuffixes:  f.bypass,
			Workers:         f.workers,
			Timeout:         time.Duration(f.timeout) * time.Second,
			Delay:           time.Duration(f.delay) * time.Millisecond,
			Proxy:           f.proxy,
			Cookies:         f.cookie,
			Headers:         f.headers,
			Method:          f.method,
			FollowRedirects: f.follow,
		}

		fzr := fuzzer.New(cfg)
		payloadCount := fzr.PayloadCount()

		if len(targetFiles) > 1 && !f.quiet {
			fmt.Fprintf(os.Stderr, "\n%s %s (%d payloads)\n", bold(">>>"), cyan(targetFile), payloadCount)
		} else if !f.quiet {
			fmt.Fprintf(os.Stderr, "%s %s\n", bold("Target:"), f.url)
			fmt.Fprintf(os.Stderr, "%s %s\n", bold("File:"), targetFile)
			encCount := len(encoding.Techniques)
			if len(f.encodings) > 0 {
				encCount = len(f.encodings)
			}
			fmt.Fprintf(os.Stderr, "%s %d (%d depths x %d encodings)\n", bold("Payloads:"), payloadCount, f.depth, encCount)
			fmt.Fprintf(os.Stderr, "%s %d goroutines | %s %ds\n", bold("Workers:"), f.workers, bold("Timeout:"), f.timeout)
			if f.proxy != "" {
				fmt.Fprintf(os.Stderr, "%s %s\n", bold("Proxy:"), f.proxy)
			}
			fmt.Fprintln(os.Stderr)
		}

		var hits int32
		var count int32
		start := time.Now()

		results := fzr.Run(func(r fuzzer.Result) {
			n := atomic.AddInt32(&count, 1)
			if r.Detection.Hit {
				atomic.AddInt32(&hits, 1)
				if f.quiet {
					fmt.Printf("[HIT] [%s] %s d=%d | %d | %s\n",
						strings.ToUpper(r.Detection.Confidence), r.Encoding, r.Depth, r.StatusCode, r.URL)
				} else {
					conf := r.Detection.Confidence
					confStr := green("[" + strings.ToUpper(conf) + "]")
					if conf == "medium" {
						confStr = yellow("[MEDIUM]")
					} else if conf == "low" {
						confStr = dim("[LOW]")
					}
					fmt.Fprintf(os.Stderr, "  %s %s %s d=%d | HTTP %d | %dB | %s\n",
						green("[HIT]"), confStr, r.Encoding, r.Depth, r.StatusCode, r.ContentLength, r.Detection.Reason)
					if r.ResponseSnippet != "" {
						snip := r.ResponseSnippet
						if len(snip) > 150 {
							snip = snip[:150]
						}
						fmt.Fprintf(os.Stderr, "    %s\n", dim(snip))
					}
				}
			} else if !f.hitsOnly && !f.quiet && n%100 == 0 {
				elapsed := time.Since(start).Seconds()
				rps := float64(n) / elapsed
				fmt.Fprintf(os.Stderr, "  %s %d/%d tested, %d hits, %.0f req/s\r",
					dim("..."), n, payloadCount, atomic.LoadInt32(&hits), rps)
			}
		})

		allResults = append(allResults, results...)
		h := int(atomic.LoadInt32(&hits))
		totalHits += h

		if !f.quiet {
			elapsed := time.Since(start)
			rps := float64(len(results)) / elapsed.Seconds()
			fmt.Fprintf(os.Stderr, "\n%s/%d in %s (%.0f req/s)\n",
				bold(fmt.Sprintf("%d hits", h)), len(results), elapsed.Round(time.Millisecond), rps)
		}
	}

	// Export
	if f.output != "" {
		toExport := allResults
		if f.hitsOnly {
			var filtered []fuzzer.Result
			for _, r := range allResults {
				if r.Detection.Hit {
					filtered = append(filtered, r)
				}
			}
			toExport = filtered
		}
		if err := output.Export(toExport, f.output, f.format); err != nil {
			fmt.Fprintf(os.Stderr, "Export error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Results saved to %s\n", cyan(f.output))
	}

	if len(targetFiles) > 1 && !f.quiet {
		fmt.Fprintf(os.Stderr, "\n%s %d total hits across %d files\n", bold("TOTAL:"), totalHits, len(targetFiles))
	}
}

func cmdScan(args []string) {
	// Parse flags, then inject default file list
	f := parseFlags(args)
	if f.url == "" {
		fmt.Fprintln(os.Stderr, "Error: URL required")
		os.Exit(1)
	}

	defaultFiles := []string{
		"/etc/passwd", "/etc/shadow", "/etc/hosts",
		"/proc/self/environ", "/proc/version",
		"win.ini", "boot.ini", ".env", "web.xml",
		"wp-config.php", ".git/config", ".git/HEAD",
	}

	// Build a new arg list with --list pointing to a temp file
	tmpFile, err := os.CreateTemp("", "liffier-scan-*.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpFile.Name())

	for _, file := range defaultFiles {
		fmt.Fprintln(tmpFile, file)
	}
	tmpFile.Close()

	// Remove the URL from the original args to avoid duplication
	var cleaned []string
	cleaned = append(cleaned, f.url, "-l", tmpFile.Name())
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == f.url {
			continue
		}
		cleaned = append(cleaned, a)
	}
	cmdFuzz(cleaned)
}

func cmdPayloads(args []string) {
	f := parseFlags(args)

	targetFiles := []string{f.file}
	if f.list != "" {
		lines, err := encoding.LoadWordlist(f.list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading wordlist: %v\n", err)
			os.Exit(1)
		}
		targetFiles = lines
	}

	for _, tf := range targetFiles {
		payloads := encoding.BuildPayloads(tf, f.depth, f.encodings, f.bypass)
		for _, p := range payloads {
			fmt.Println(p.Value)
		}
	}
}

func cmdEncodings() {
	techs := encoding.ListEncodings()

	// Group by category
	fmt.Printf("\n%s (%d techniques)\n\n", bold("Traversal Encoding Techniques"), len(techs))
	fmt.Printf("  %-30s  %s\n", bold("NAME"), bold("SEQUENCE"))
	fmt.Printf("  %-30s  %s\n", strings.Repeat("-", 30), strings.Repeat("-", 40))

	// Sort by name for readability
	sorted := make([]encoding.Technique, len(techs))
	copy(sorted, techs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	for _, t := range sorted {
		seq := t.Sequence
		if len(seq) > 40 {
			seq = seq[:37] + "..."
		}
		fmt.Printf("  %-30s  %s\n", cyan(t.Name), seq)
	}
	fmt.Printf("\n  Total: %d techniques\n\n", len(techs))
}
