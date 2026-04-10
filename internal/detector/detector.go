package detector

import (
	"math"
	"strings"
)

// Detection is the result of analyzing a response for traversal success.
type Detection struct {
	Hit              bool
	Confidence       string // "high", "medium", "low"
	Reason           string
	MatchedSignature string
}

// fileSignatures maps target file basenames to content signatures.
var fileSignatures = map[string][]string{
	"passwd":  {"root:x:0:0:", "root:*:0:0:", "daemon:", "nobody:"},
	"shadow":  {"root:$", "root:!", "root:*:"},
	"hosts":   {"127.0.0.1", "localhost"},
	"environ": {"PATH=", "HOME=", "USER="},
	"version": {"Linux version"},
	"win.ini": {"[fonts]", "[extensions]", "[files]"},
	"boot.ini": {"[boot loader]", "[operating systems]"},
	".env":    {"APP_KEY=", "DB_PASSWORD=", "DB_HOST="},
	"web.xml": {"<web-app", "<servlet"},
}

// errorPatterns in response bodies that indicate failure.
var errorPatterns = []string{
	"404", "not found", "403", "forbidden", "access denied",
	"400", "bad request", "500", "internal server error",
}

// Analyze checks an HTTP response for signs of successful path traversal.
func Analyze(statusCode int, body string, targetFile string, baselineLength int) Detection {
	if statusCode >= 400 {
		return Detection{Hit: false, Confidence: "high", Reason: "HTTP " + strings.TrimSpace(string(rune(statusCode+'0')))}
	}

	// Extract basename from target file
	basename := targetFile
	if idx := strings.LastIndex(targetFile, "/"); idx >= 0 {
		basename = targetFile[idx+1:]
	}
	if idx := strings.LastIndex(basename, "\\"); idx >= 0 {
		basename = basename[idx+1:]
	}

	// Check for error patterns in body (first 2000 chars)
	snippet := body
	if len(snippet) > 2000 {
		snippet = snippet[:2000]
	}
	lower := strings.ToLower(snippet)
	for _, pat := range errorPatterns {
		if strings.Contains(lower, pat) {
			return Detection{Hit: false, Confidence: "medium", Reason: "Error pattern: " + pat}
		}
	}

	// Check file-specific signatures
	for file, sigs := range fileSignatures {
		if basename == file || strings.HasSuffix(targetFile, file) {
			for _, sig := range sigs {
				if strings.Contains(body, sig) {
					return Detection{
						Hit:              true,
						Confidence:       "high",
						Reason:           "Signature match for " + file,
						MatchedSignature: sig,
					}
				}
			}
			// File matched but no signatures found
			if len(sigs) > 0 {
				break
			}
			if len(strings.TrimSpace(body)) > 0 && statusCode == 200 {
				return Detection{
					Hit:        true,
					Confidence: "medium",
					Reason:     "Non-empty 200 for " + file + " (no specific signature)",
				}
			}
		}
	}

	// Baseline length comparison
	if baselineLength > 0 && len(body) != baselineLength {
		diff := math.Abs(float64(len(body) - baselineLength))
		ratio := diff / math.Max(float64(baselineLength), 1)
		if ratio > 0.3 && len(body) > 50 {
			return Detection{
				Hit:        true,
				Confidence: "low",
				Reason:     "Response length anomaly vs baseline",
			}
		}
	}

	return Detection{Hit: false, Confidence: "medium", Reason: "No indicators"}
}
