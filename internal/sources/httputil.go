package sources

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

func buildHTTPClient(proxy string, timeoutSecs int) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	if proxy != "" {
		if proxyURL, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	timeout := time.Duration(timeoutSecs) * time.Second
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
