package sources

import (
	"context"
	"encoding/json"
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

type SecurityTrailsSource struct{}

func (s *SecurityTrailsSource) Name() string { return "securitytrails" }

func (s *SecurityTrailsSource) ConfigCheck(cfg *config.Config) (bool, string) {
	if cfg.Sources.SecurityTrails.Email == "" {
		return false, "email not set in config"
	}
	if cfg.Sources.SecurityTrails.Password == "" {
		return false, "password not set in config"
	}
	if cfg.Capsolver.Token == "" {
		return false, "capsolver token not set in config"
	}
	return true, ""
}

func (s *SecurityTrailsSource) Run(ctx context.Context, domain string, cfg *config.Config) Result {
	start := time.Now()
	subdomains, err := s.fetch(ctx, domain, cfg)
	dur := time.Since(start)
	if err != nil {
		logger.Errorf("[securitytrails] %v", err)
		return Result{Source: s.Name(), Status: StatusFailed, Err: err, Duration: dur}
	}
	return Result{Source: s.Name(), Subdomains: subdomains, Status: StatusOK, Duration: dur}
}

const (
	stBaseURL = "https://securitytrails.com"
	stAPIBase = "https://securitytrails.com/_next/data/"
	stUA      = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
)

type stSession struct {
	cfg       *config.Config
	capsolver *helper.CapsolverClient
	client    *http.Client
	jar       *simpleCookieJar
	userAgent string
	// proxy is the proxy used for every request to securitytrails.com.
	// It must match the proxy Capsolver used to solve the challenge, because
	// Cloudflare binds cf_clearance to the IP that solved it.
	proxy string
}

func (s *SecurityTrailsSource) fetch(ctx context.Context, domain string, cfg *config.Config) ([]string, error) {
	// SecurityTrails always requires Capsolver. All requests to the target site
	// must use the same proxy that Capsolver used to obtain cf_clearance —
	// Cloudflare binds the cookie to that specific IP. Using a different proxy
	// (global.proxy) causes an immediate re-challenge on every request.
	siteProxy := cfg.Capsolver.Proxy
	if siteProxy == "" {
		logger.Warningf("[securitytrails] capsolver_proxy is not set — requests will go direct; cf_clearance may be rejected if Capsolver solved via a different IP")
	}

	logger.Debugf("[securitytrails] using email=%s password=%s capsolver_token=%s capsolver_proxy=%s (also used as site proxy)",
		cfg.Sources.SecurityTrails.Email,
		cfg.Sources.SecurityTrails.Password,
		cfg.Capsolver.Token,
		siteProxy,
	)

	jar := newSimpleCookieJar()
	sess := &stSession{
		cfg:       cfg,
		capsolver: helper.NewCapsolverClient(cfg.Capsolver.Token, cfg.Capsolver.Proxy),
		jar:       jar,
		client:    buildHTTPClientWithJar(siteProxy, cfg.Global.Timeout, jar),
		userAgent: stUA,
		proxy:     siteProxy,
	}

	if err := sess.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	buildID, err := sess.getBuildID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get build ID: %w", err)
	}

	return sess.fetchSubdomains(ctx, domain, buildID)
}

func (sess *stSession) doGet(ctx context.Context, rawURL string, extraHeaders map[string]string) ([]byte, int, error) {
	for retry := 0; retry < sess.cfg.Global.Retry; retry++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", sess.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}

		resp, err := httpdebug.Do(sess.client, req, sess.proxy)
		if err != nil {
			logger.Warningf("[securitytrails] request error (attempt %d/%d): %v", retry+1, sess.cfg.Global.Retry, err)
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 403 || strings.Contains(string(bodyBytes), "Just a moment") ||
			strings.Contains(string(bodyBytes), "cf-browser-verification") {
			logger.Warning("[securitytrails] Cloudflare challenge detected, solving...")
			cfClearance, ua, err := sess.capsolver.SolveChallenge(ctx, rawURL, string(bodyBytes))
			if err != nil {
				return nil, 0, fmt.Errorf("capsolver failed: %w", err)
			}
			sess.jar.Set("securitytrails.com", "cf_clearance", cfClearance)
			if ua != "" {
				sess.userAgent = ua
			}
			continue
		}
		return bodyBytes, resp.StatusCode, nil
	}
	return nil, 0, fmt.Errorf("max retries exceeded for %s", rawURL)
}

func (sess *stSession) authenticate(ctx context.Context) error {
	logger.Info("[securitytrails] authenticating...")

	// Get homepage first to acquire cf_clearance if needed
	_, _, err := sess.doGet(ctx, stBaseURL, nil)
	if err != nil {
		return err
	}

	// POST login
	loginURL := stBaseURL + "/api/auth/login"
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`,
		sess.cfg.Sources.SecurityTrails.Email,
		sess.cfg.Sources.SecurityTrails.Password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(loginBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", sess.userAgent)

	resp, err := httpdebug.Do(sess.client, req, sess.proxy)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("login returned HTTP %d", resp.StatusCode)
	}

	logger.Success("[securitytrails] authentication successful")
	return nil
}

func (sess *stSession) getBuildID(ctx context.Context) (string, error) {
	logger.Info("[securitytrails] extracting build ID...")
	bodyBytes, status, err := sess.doGet(ctx, stBaseURL+"/app/account", nil)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("account page returned HTTP %d", status)
	}

	re := regexp.MustCompile(`src="/_next/static/([a-zA-Z0-9]+)/_buildManifest\.js"`)
	m := re.FindSubmatch(bodyBytes)
	if m == nil {
		return "", fmt.Errorf("build ID not found in account page")
	}
	buildID := string(m[1])
	logger.Successf("[securitytrails] build ID: %s", buildID)
	return buildID, nil
}

func (sess *stSession) fetchSubdomains(ctx context.Context, domain, buildID string) ([]string, error) {
	apiURL := fmt.Sprintf("%s%s/list/apex_domain/%s.json", stAPIBase, buildID, domain)

	seen := map[string]bool{}
	var results []string
	page := 1
	var totalPages int

	for {
		if totalPages > 0 {
			logger.Infof("[securitytrails] fetching page %d/%d...", page, totalPages)
		} else {
			logger.Infof("[securitytrails] fetching page %d...", page)
		}

		fullURL := fmt.Sprintf("%s?page=%d&domain=%s", apiURL, page, domain)
		bodyBytes, status, err := sess.doGet(ctx, fullURL, nil)
		if err != nil {
			return results, err
		}

		if status == 504 {
			logger.Warning("[securitytrails] gateway timeout, retrying...")
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if status != 200 {
			return results, fmt.Errorf("HTTP %d on page %d", status, page)
		}

		var data struct {
			PageProps struct {
				ApexDomainData struct {
					Data struct {
						Records []struct {
							Hostname string `json:"hostname"`
						} `json:"records"`
						Meta struct {
							TotalPages int `json:"total_pages"`
						} `json:"meta"`
					} `json:"data"`
				} `json:"apexDomainData"`
			} `json:"pageProps"`
		}
		if err := json.Unmarshal(bodyBytes, &data); err != nil {
			return results, fmt.Errorf("JSON parse error on page %d: %w", page, err)
		}

		records := data.PageProps.ApexDomainData.Data.Records
		totalPages = data.PageProps.ApexDomainData.Data.Meta.TotalPages
		logger.Successf("[securitytrails] page %d/%d: %d records", page, totalPages, len(records))

		for _, rec := range records {
			if rec.Hostname != "" && !seen[rec.Hostname] {
				seen[rec.Hostname] = true
				results = append(results, rec.Hostname)
			}
		}

		if page >= totalPages {
			break
		}
		page++
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	logger.Successf("[securitytrails] found %d subdomains for %s", len(results), domain)
	return results, nil
}
