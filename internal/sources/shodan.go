package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/AliHzSec/subhunter/internal/config"
	"github.com/AliHzSec/subhunter/internal/httpdebug"
	"github.com/AliHzSec/subhunter/internal/logger"
)

type ShodanSource struct{}

func (s *ShodanSource) Name() string { return "shodan" }

func (s *ShodanSource) ConfigCheck(cfg *config.Config) (bool, string) {
	if cfg.Sources.Shodan.APIKey == "" {
		return false, "api_key not set in config"
	}
	return true, ""
}

func (s *ShodanSource) Run(ctx context.Context, domain string, cfg *config.Config) Result {
	start := time.Now()
	subdomains, err := s.fetch(ctx, domain, cfg)
	dur := time.Since(start)
	if err != nil {
		logger.Errorf("[shodan] %v", err)
		return Result{Source: s.Name(), Status: StatusFailed, Err: err, Duration: dur}
	}
	return Result{Source: s.Name(), Subdomains: subdomains, Status: StatusOK, Duration: dur}
}

func (s *ShodanSource) fetch(ctx context.Context, domain string, cfg *config.Config) ([]string, error) {
	logger.Debugf("[shodan] using api_key=%s proxy=%s", cfg.Sources.Shodan.APIKey, cfg.Global.Proxy)

	apiURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s", domain)
	client := buildHTTPClient(cfg.Global.Proxy, cfg.Global.Timeout)

	var lastErr error
	for attempt := 0; attempt < cfg.Global.Retry; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, err
		}
		q := url.Values{"key": {cfg.Sources.Shodan.APIKey}}
		req.URL.RawQuery = q.Encode()
		req.Header.Set("Accept", "application/json")

		resp, err := httpdebug.Do(client, req, cfg.Global.Proxy)
		if err != nil {
			lastErr = err
			logger.Warningf("[shodan] request error (attempt %d/%d): %v", attempt+1, cfg.Global.Retry, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 401 {
			return nil, fmt.Errorf("invalid Shodan API key")
		}
		if resp.StatusCode == 404 {
			logger.Warningf("[shodan] no subdomains found for %s", domain)
			return nil, nil
		}
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			logger.Warningf("[shodan] HTTP %d (attempt %d/%d)", resp.StatusCode, attempt+1, cfg.Global.Retry)
			continue
		}

		var data struct {
			Subdomains []string `json:"subdomains"`
			Data       []struct {
				Subdomain string `json:"subdomain"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("JSON parse error: %w", err)
		}

		seen := map[string]bool{}
		var results []string

		for _, sub := range data.Subdomains {
			if sub == "" {
				continue
			}
			fqdn := sub + "." + domain
			if !seen[fqdn] {
				seen[fqdn] = true
				results = append(results, fqdn)
			}
		}
		for _, item := range data.Data {
			if item.Subdomain == "" {
				continue
			}
			fqdn := item.Subdomain + "." + domain
			if !seen[fqdn] {
				seen[fqdn] = true
				results = append(results, fqdn)
			}
		}

		logger.Successf("[shodan] found %d subdomains for %s", len(results), domain)
		return results, nil
	}
	return nil, lastErr
}
