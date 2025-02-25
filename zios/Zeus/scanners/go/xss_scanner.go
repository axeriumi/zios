package main

import (
    "fmt"
    "net/http"
    "sync"
    "encoding/json"
    "strings"
    "time"
    "os"
    "golang.org/x/net/html"
    "crypto/tls"
)

type Vulnerability struct {
    Type     string `json:"type"`
    Payload  string `json:"payload"`
    Location string `json:"location"`
    Risk     string `json:"risk"`
}

type ScanResult struct {
    URL            string         `json:"url"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    TimeStamp      string         `json:"timestamp"`
}

var payloads = []string{
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "' onclick='alert(1)",
    "\" onclick=\"alert(1)",
    "' onfocus='alert(1)",
    "\" onfocus=\"alert(1)",
    "<iframe src=\"javascript:alert(1)\">",
    "<object data=\"javascript:alert(1)\">",
}

func checkReflectedXSS(url, payload string, wg *sync.WaitGroup, results chan<- Vulnerability) {
    defer wg.Done()

    client := &http.Client{
        Timeout: time.Second * 10,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }

    // Test different injection points
    testURLs := []string{
        url + "?" + payload,
        url + "?q=" + payload,
        url + "?search=" + payload,
        url + "?id=" + payload,
    }

    for _, testURL := range testURLs {
        resp, err := client.Get(testURL)
        if err != nil {
            continue
        }
        defer resp.Body.Close()

        doc, err := html.Parse(resp.Body)
        if err != nil {
            continue
        }

        var checkNode func(*html.Node)
        checkNode = func(n *html.Node) {
            if n.Type == html.ElementNode {
                // Check attributes
                for _, attr := range n.Attr {
                    if strings.Contains(attr.Val, payload) {
                        results <- Vulnerability{
                            Type:     "reflected_xss",
                            Payload:  payload,
                            Location: fmt.Sprintf("attribute %s in tag %s", attr.Key, n.Data),
                            Risk:     "high",
                        }
                        return
                    }
                }
            } else if n.Type == html.TextNode {
                // Check text content
                if strings.Contains(n.Data, payload) {
                    results <- Vulnerability{
                        Type:     "reflected_xss",
                        Payload:  payload,
                        Location: "text content",
                        Risk:     "high",
                    }
                    return
                }
            }

            for c := n.FirstChild; c != nil; c = c.NextSibling {
                checkNode(c)
            }
        }

        checkNode(doc)
    }
}

func checkDOMXSS(url string, wg *sync.WaitGroup, results chan<- Vulnerability) {
    defer wg.Done()

    client := &http.Client{
        Timeout: time.Second * 10,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }

    resp, err := client.Get(url)
    if err != nil {
        return
    }
    defer resp.Body.Close()

    doc, err := html.Parse(resp.Body)
    if err != nil {
        return
    }

    riskySinks := []string{
        "eval(",
        "innerHTML",
        "outerHTML",
        "document.write(",
        "document.writeln(",
        "location.hash",
        "location.search",
    }

    var checkNode func(*html.Node)
    checkNode = func(n *html.Node) {
        if n.Type == html.ElementNode {
            // Check for event handlers
            for _, attr := range n.Attr {
                if strings.HasPrefix(attr.Key, "on") {
                    results <- Vulnerability{
                        Type:     "dom_xss",
                        Payload:  attr.Val,
                        Location: fmt.Sprintf("event handler %s in tag %s", attr.Key, n.Data),
                        Risk:     "medium",
                    }
                }
            }

            // Check for script tags
            if n.Data == "script" {
                for _, sink := range riskySinks {
                    if strings.Contains(n.FirstChild.Data, sink) {
                        results <- Vulnerability{
                            Type:     "dom_xss",
                            Payload:  sink,
                            Location: "script content",
                            Risk:     "high",
                        }
                    }
                }
            }
        }

        for c := n.FirstChild; c != nil; c = c.NextSibling {
            checkNode(c)
        }
    }

    checkNode(doc)
}

func main() {
    if len(os.Args) != 2 {
        fmt.Println("Usage: xss_scanner <url>")
        os.Exit(1)
    }

    url := os.Args[1]
    results := make(chan Vulnerability, 100)
    var wg sync.WaitGroup

    // Check for reflected XSS
    for _, payload := range payloads {
        wg.Add(1)
        go checkReflectedXSS(url, payload, &wg, results)
    }

    // Check for DOM-based XSS
    wg.Add(1)
    go checkDOMXSS(url, &wg, results)

    // Wait in a separate goroutine
    go func() {
        wg.Wait()
        close(results)
    }()

    // Collect results
    scanResult := ScanResult{
        URL:       url,
        TimeStamp: time.Now().Format(time.RFC3339),
    }

    for vuln := range results {
        scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
    }

    // Output results as JSON
    jsonResult, _ := json.MarshalIndent(scanResult, "", "  ")
    fmt.Println(string(jsonResult))
} 