package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AliHzSec/subhunter/internal/config"
	"github.com/AliHzSec/subhunter/internal/httpdebug"
	"github.com/AliHzSec/subhunter/internal/logger"
)

type C99Source struct{}

func (s *C99Source) Name() string { return "c99" }

func (s *C99Source) ConfigCheck(cfg *config.Config) (bool, string) {
	if cfg.Sources.C99.APIKey == "" {
		return false, "api_key not set in config"
	}
	return true, ""
}

func (s *C99Source) Run(ctx context.Context, domain string, cfg *config.Config) Result {
	start := time.Now()
	subdomains, err := s.fetch(ctx, domain, cfg)
	dur := time.Since(start)
	if err != nil {
		logger.Errorf("[c99] %v", err)
		return Result{Source: s.Name(), Status: StatusFailed, Err: err, Duration: dur}
	}
	return Result{Source: s.Name(), Subdomains: subdomains, Status: StatusOK, Duration: dur}
}

func (s *C99Source) fetch(ctx context.Context, domain string, cfg *config.Config) ([]string, error) {
	logger.Debugf("[c99] using api_key=%s proxy=%s", cfg.Sources.C99.APIKey, cfg.Global.Proxy)

	client := buildHTTPClient(cfg.Global.Proxy, cfg.Global.Timeout)

	var lastErr error
	for attempt := 0; attempt < cfg.Global.Retry; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.c99.nl/subdomainfinder", nil)
		if err != nil {
			return nil, err
		}
		q := url.Values{
			"key":    {cfg.Sources.C99.APIKey},
			"domain": {domain},
			"json":   {"true"},
		}
		req.URL.RawQuery = q.Encode()
		req.Header.Set("Accept", "application/json")

		resp, err := httpdebug.Do(client, req, cfg.Global.Proxy)
		if err != nil {
			lastErr = err
			logger.Warningf("[c99] request error (attempt %d/%d): %v", attempt+1, cfg.Global.Retry, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			logger.Warningf("[c99] HTTP %d (attempt %d/%d)", resp.StatusCode, attempt+1, cfg.Global.Retry)
			continue
		}

		var data struct {
			Success    bool   `json:"success"`
			Error      string `json:"error"`
			Subdomains []struct {
				Subdomain string `json:"subdomain"`
			} `json:"subdomains"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("JSON parse error: %w", err)
		}

		if !data.Success {
			if strings.Contains(data.Error, "No subdomains found") {
				logger.Warningf("[c99] no subdomains found for %s", domain)
				return nil, nil
			}
			return nil, fmt.Errorf("API error: %s", data.Error)
		}

		seen := map[string]bool{}
		var results []string
		for _, item := range data.Subdomains {
			sub := item.Subdomain
			if sub == "" {
				continue
			}
			if !seen[sub] {
				seen[sub] = true
				results = append(results, sub)
			}
		}
		logger.Successf("[c99] found %d subdomains for %s", len(results), domain)
		return results, nil
	}
	return nil, lastErr
}
