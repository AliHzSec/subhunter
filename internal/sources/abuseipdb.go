package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/AliHzSec/subhunter/internal/config"
	"github.com/AliHzSec/subhunter/internal/helper"
	"github.com/AliHzSec/subhunter/internal/httpdebug"
	"github.com/AliHzSec/subhunter/internal/logger"
)

type AbuseIPDBSource struct{}

func (s *AbuseIPDBSource) Name() string { return "abuseipdb" }

func (s *AbuseIPDBSource) ConfigCheck(cfg *config.Config) (bool, string) {
	if cfg.Sources.AbuseIPDB.SessionCookie == "" {
		return false, "session_cookie not set in config"
	}
	return true, ""
}

func (s *AbuseIPDBSource) Run(ctx context.Context, domain string, cfg *config.Config) Result {
	start := time.Now()
	subdomains, err := s.fetch(ctx, domain, cfg)
	dur := time.Since(start)
	if err != nil {
		logger.Errorf("[abuseipdb] %v", err)
		return Result{Source: s.Name(), Status: StatusFailed, Err: err, Duration: dur}
	}
	return Result{Source: s.Name(), Subdomains: subdomains, Status: StatusOK, Duration: dur}
}

func (s *AbuseIPDBSource) fetch(ctx context.Context, domain string, cfg *config.Config) ([]string, error) {
	capsolverActive := cfg.Sources.AbuseIPDB.UseCapsolver && cfg.Capsolver.Token != ""

	// When Capsolver is active, all requests to the target site must use the same
	// proxy Capsolver used to solve the challenge — Cloudflare binds cf_clearance
	// to that specific IP. Using global.proxy (a different IP) causes an immediate
	// re-challenge on every follow-up request.
	// When Capsolver is not active, fall back to the general proxy as normal.
	var siteProxy string
	if capsolverActive {
		siteProxy = cfg.Capsolver.Proxy
		if siteProxy == "" {
			logger.Warningf("[abuseipdb] capsolver is enabled but capsolver_proxy is not set — requests will go direct; cf_clearance may be rejected if Capsolver solved via a different IP")
		}
	} else {
		siteProxy = cfg.Global.Proxy
	}

	logger.Debugf("[abuseipdb] using session_cookie=%s site_proxy=%s capsolver_active=%v",
		cfg.Sources.AbuseIPDB.SessionCookie,
		siteProxy,
		capsolverActive,
	)

	jar := newSimpleCookieJar()
	jar.Set("www.abuseipdb.com", "abuseipdb_session", cfg.Sources.AbuseIPDB.SessionCookie)

	client := buildHTTPClientWithJar(siteProxy, cfg.Global.Timeout, jar)

	var caps *helper.CapsolverClient
	if capsolverActive {
		caps = helper.NewCapsolverClient(cfg.Capsolver.Token, cfg.Capsolver.Proxy)
		logger.Debugf("[abuseipdb] capsolver enabled: token=%s capsolver_proxy=%s",
			cfg.Capsolver.Token,
			cfg.Capsolver.Proxy,
		)
	}

	targetURL := fmt.Sprintf("https://www.abuseipdb.com/whois/%s", domain)
	logger.Infof("[abuseipdb] fetching subdomains for %s", domain)

	bodyBytes, err := s.makeRequest(ctx, client, jar, caps, targetURL, cfg.Global.Retry, siteProxy)
	if err != nil {
		return nil, err
	}

	results := extractAbuseIPDBSubdomains(string(bodyBytes), domain)
	if len(results) == 0 {
		logger.Warningf("[abuseipdb] no subdomains found for %s", domain)
	} else {
		logger.Successf("[abuseipdb] found %d subdomains for %s", len(results), domain)
	}
	return results, nil
}

func (s *AbuseIPDBSource) makeRequest(
	ctx context.Context,
	client *http.Client,
	jar *simpleCookieJar,
	caps *helper.CapsolverClient,
	targetURL string,
	maxRetries int,
	proxy string,
) ([]byte, error) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	for retry := 0; retry < maxRetries; retry++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err := httpdebug.Do(client, req, proxy)
		if err != nil {
			logger.Warningf("[abuseipdb] request error (attempt %d/%d): %v", retry+1, maxRetries, err)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(bodyBytes)

		if resp.StatusCode == 403 || strings.Contains(body, "Just a moment") || strings.Contains(body, "cf-browser-verification") {
			if caps == nil {
				return nil, fmt.Errorf("Cloudflare challenge detected but no Capsolver configured")
			}
			logger.Warning("[abuseipdb] Cloudflare challenge detected, solving...")
			cfClearance, newUA, err := caps.SolveChallenge(ctx, targetURL, body)
			if err != nil {
				return nil, fmt.Errorf("capsolver failed: %w", err)
			}
			jar.Set("www.abuseipdb.com", "cf_clearance", cfClearance)
			if newUA != "" {
				ua = newUA
			}
			continue
		}

		if resp.StatusCode == 403 {
			return nil, fmt.Errorf("HTTP 403 — session cookie may be invalid or expired")
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return bodyBytes, nil
	}
	return nil, fmt.Errorf("max retries exceeded")
}

func extractAbuseIPDBSubdomains(html, domain string) []string {
	if !strings.Contains(html, "<h4>Subdomains</h4>") {
		return nil
	}

	re := regexp.MustCompile(`(?s)<h4>Subdomains</h4>(.*?)</h[24]>`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		return nil
	}

	liRe := regexp.MustCompile(`<li>([^<]+)</li>`)
	matches := liRe.FindAllStringSubmatch(m[1], -1)

	seen := map[string]bool{}
	var results []string
	for _, match := range matches {
		sub := strings.TrimSpace(match[1])
		if sub == "" {
			continue
		}
		fqdn := sub + "." + domain
		if !seen[fqdn] {
			seen[fqdn] = true
			results = append(results, fqdn)
		}
	}
	return results
}
