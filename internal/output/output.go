package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/momenbasel/liffier/internal/fuzzer"
)

type record struct {
	URL              string `json:"url"`
	Payload          string `json:"payload"`
	Encoding         string `json:"encoding"`
	Depth            int    `json:"depth"`
	Suffix           string `json:"suffix"`
	StatusCode       int    `json:"status_code"`
	ContentLength    int    `json:"content_length"`
	ElapsedMs        int64  `json:"elapsed_ms"`
	Hit              bool   `json:"hit"`
	Confidence       string `json:"confidence"`
	Reason           string `json:"reason"`
	MatchedSignature string `json:"matched_signature"`
	Snippet          string `json:"response_snippet"`
	Error            string `json:"error"`
}

func toRecord(r fuzzer.Result) record {
	return record{
		URL:              r.URL,
		Payload:          r.Payload,
		Encoding:         r.Encoding,
		Depth:            r.Depth,
		Suffix:           r.Suffix,
		StatusCode:       r.StatusCode,
		ContentLength:    r.ContentLength,
		ElapsedMs:        r.ElapsedMs,
		Hit:              r.Detection.Hit,
		Confidence:       r.Detection.Confidence,
		Reason:           r.Detection.Reason,
		MatchedSignature: r.Detection.MatchedSignature,
		Snippet:          r.ResponseSnippet,
		Error:            r.Error,
	}
}

// ExportJSON writes results as indented JSON.
func ExportJSON(results []fuzzer.Result, path string) error {
	records := make([]record, len(results))
	for i, r := range results {
		records[i] = toRecord(r)
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ExportJSONL writes results as one JSON object per line.
func ExportJSONL(results []fuzzer.Result, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range results {
		if err := enc.Encode(toRecord(r)); err != nil {
			return err
		}
	}
	return nil
}

// ExportCSV writes results as CSV.
func ExportCSV(results []fuzzer.Result, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"url", "payload", "encoding", "depth", "suffix", "status_code", "content_length", "elapsed_ms", "hit", "confidence", "reason", "error"}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		rec := toRecord(r)
		row := []string{
			rec.URL, rec.Payload, rec.Encoding,
			strconv.Itoa(rec.Depth), rec.Suffix,
			strconv.Itoa(rec.StatusCode), strconv.Itoa(rec.ContentLength),
			strconv.FormatInt(rec.ElapsedMs, 10),
			strconv.FormatBool(rec.Hit), rec.Confidence, rec.Reason, rec.Error,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// Export dispatches to the correct format.
func Export(results []fuzzer.Result, path string, format string) error {
	switch format {
	case "json":
		return ExportJSON(results, path)
	case "jsonl":
		return ExportJSONL(results, path)
	case "csv":
		return ExportCSV(results, path)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}
