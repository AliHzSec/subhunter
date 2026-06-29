package httpdebug

import (
	"bytes"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AliHzSec/subhunter/internal/logger"
)

const maxBodyLog = 2000

// Do executes req using client. When debug mode is on, it logs the full
// request (method, URL, proxy, headers, body) and response (status, headers,
// body, timing) to stderr — no truncation below maxBodyLog, no value masking.
// proxy is the proxy URL string configured for this particular client; pass ""
// if the client makes direct connections (it will display as "none").
func Do(client *http.Client, req *http.Request, proxy string) (*http.Response, error) {
	if !logger.DebugMode {
		return client.Do(req)
	}

	// Buffer request body so the HTTP client can still send it after we read it.
	var reqBody string
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(b))
		reqBody = string(b)
	}

	proxyDisplay := proxy
	if proxyDisplay == "" {
		proxyDisplay = "none"
	}

	logger.Debugf("→ %s %s", req.Method, req.URL.String())
	logger.Debugf("  proxy: %s", proxyDisplay)

	// Log request headers in stable sorted order.
	hdrKeys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		hdrKeys = append(hdrKeys, k)
	}
	sort.Strings(hdrKeys)
	for _, k := range hdrKeys {
		logger.Debugf("  req-header: %s: %s", k, strings.Join(req.Header[k], ", "))
	}
	if reqBody != "" {
		logger.Debugf("  req-body: %s", reqBody)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		logger.Debugf("  error after %.3fs: %v", elapsed.Seconds(), err)
		return resp, err
	}

	// Buffer response body so the caller can still read it.
	respBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(respBytes))

	logger.Debugf("← %d (%.3fs)", resp.StatusCode, elapsed.Seconds())

	// Log response headers.
	hdrKeys = hdrKeys[:0]
	for k := range resp.Header {
		hdrKeys = append(hdrKeys, k)
	}
	sort.Strings(hdrKeys)
	for _, k := range hdrKeys {
		logger.Debugf("  resp-header: %s: %s", k, strings.Join(resp.Header[k], ", "))
	}

	body := string(respBytes)
	if len(body) > maxBodyLog {
		logger.Debugf("  resp-body (truncated at %d chars): %s...", maxBodyLog, body[:maxBodyLog])
	} else {
		logger.Debugf("  resp-body: %s", body)
	}

	return resp, nil
}
