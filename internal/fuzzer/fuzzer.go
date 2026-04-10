package fuzzer

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/momenbasel/liffier/internal/detector"
	"github.com/momenbasel/liffier/internal/encoding"
)

// Result is the outcome of a single fuzz attempt.
type Result struct {
	URL             string
	Payload         string
	Encoding        string
	Depth           int
	Suffix          string
	StatusCode      int
	ContentLength   int
	ElapsedMs       int64
	Detection       detector.Detection
	ResponseSnippet string
	Error           string
}

// Config holds fuzzer settings.
type Config struct {
	URL              string
	TargetFile       string
	MaxDepth         int
	Encodings        []string
	BypassSuffixes   bool
	Workers          int
	Timeout          time.Duration
	Delay            time.Duration
	Proxy            string
	Cookies          string
	Headers          map[string]string
	Method           string
	FollowRedirects  bool
	SnippetLength    int
}

// Fuzzer runs path traversal payloads against a target.
type Fuzzer struct {
	config         Config
	client         *http.Client
	baselineLength int
}

// New creates a Fuzzer from the given config.
func New(cfg Config) *Fuzzer {
	if cfg.Method == "" {
		cfg.Method = "GET"
	}
	if cfg.SnippetLength == 0 {
		cfg.SnippetLength = 200
	}
	if cfg.Workers == 0 {
		cfg.Workers = 10
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: cfg.Workers,
	}
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Fuzzer{config: cfg, client: client}
}

func (f *Fuzzer) fetchBaseline() {
	testURL := f.config.URL + "nonexistent_baseline_12345"
	req, err := f.buildRequest(testURL)
	if err != nil {
		return
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	f.baselineLength = len(body)
}

func (f *Fuzzer) buildRequest(targetURL string) (*http.Request, error) {
	req, err := http.NewRequest(f.config.Method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; liffier/2.0)")
	if f.config.Cookies != "" {
		req.Header.Set("Cookie", f.config.Cookies)
	}
	for k, v := range f.config.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (f *Fuzzer) fuzzOne(p encoding.Payload) Result {
	targetURL := f.config.URL + p.Value

	req, err := f.buildRequest(targetURL)
	if err != nil {
		return Result{
			URL: targetURL, Payload: p.Value, Encoding: p.Encoding,
			Depth: p.Depth, Suffix: p.Suffix, Error: err.Error(),
			Detection: detector.Detection{Confidence: "high", Reason: err.Error()},
		}
	}

	start := time.Now()
	resp, err := f.client.Do(req)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return Result{
			URL: targetURL, Payload: p.Value, Encoding: p.Encoding,
			Depth: p.Depth, Suffix: p.Suffix, ElapsedMs: elapsed,
			Error: err.Error(),
			Detection: detector.Detection{Confidence: "high", Reason: err.Error()},
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	det := detector.Analyze(resp.StatusCode, bodyStr, f.config.TargetFile, f.baselineLength)

	snippet := bodyStr
	if len(snippet) > f.config.SnippetLength {
		snippet = snippet[:f.config.SnippetLength]
	}

	return Result{
		URL:             targetURL,
		Payload:         p.Value,
		Encoding:        p.Encoding,
		Depth:           p.Depth,
		Suffix:          p.Suffix,
		StatusCode:      resp.StatusCode,
		ContentLength:   len(body),
		ElapsedMs:       elapsed,
		Detection:       det,
		ResponseSnippet: snippet,
	}
}

// Run executes the fuzzing campaign and calls callback for each result.
func (f *Fuzzer) Run(callback func(Result)) []Result {
	payloads := encoding.BuildPayloads(
		f.config.TargetFile,
		f.config.MaxDepth,
		f.config.Encodings,
		f.config.BypassSuffixes,
	)

	f.fetchBaseline()

	results := make([]Result, 0, len(payloads))
	var mu sync.Mutex

	sem := make(chan struct{}, f.config.Workers)
	var wg sync.WaitGroup

	for i, p := range payloads {
		if f.config.Delay > 0 && i > 0 {
			time.Sleep(f.config.Delay)
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(payload encoding.Payload) {
			defer wg.Done()
			defer func() { <-sem }()

			result := f.fuzzOne(payload)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			if callback != nil {
				callback(result)
			}
		}(p)
	}

	wg.Wait()
	return results
}

// PayloadCount returns how many payloads will be generated.
func (f *Fuzzer) PayloadCount() int {
	return len(encoding.BuildPayloads(
		f.config.TargetFile,
		f.config.MaxDepth,
		f.config.Encodings,
		f.config.BypassSuffixes,
	))
}

// FormatStatusCode returns a display string for a status code.
func FormatStatusCode(code int) string {
	if code == 0 {
		return "ERR"
	}
	return fmt.Sprintf("%d", code)
}
