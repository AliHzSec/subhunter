package sources

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AliHzSec/subhunter/internal/config"
	"github.com/AliHzSec/subhunter/internal/httpdebug"
	"github.com/AliHzSec/subhunter/internal/logger"
)

var cloudSources = map[string]string{
	"amazon":       "http://kaeferjaeger.gay/sni-ip-ranges/amazon/ipv4_merged_sni.txt",
	"digitalocean": "http://kaeferjaeger.gay/sni-ip-ranges/digitalocean/ipv4_merged_sni.txt",
	"microsoft":    "http://kaeferjaeger.gay/sni-ip-ranges/microsoft/ipv4_merged_sni.txt",
	"google":       "http://kaeferjaeger.gay/sni-ip-ranges/google/ipv4_merged_sni.txt",
	"oracle":       "http://kaeferjaeger.gay/sni-ip-ranges/oracle/ipv4_merged_sni.txt",
}

const cloudIndexURL = "http://kaeferjaeger.gay/?dir=sni-ip-ranges"

type CloudSNISource struct{}

func (s *CloudSNISource) Name() string { return "cloudsni" }

func (s *CloudSNISource) ConfigCheck(cfg *config.Config) (bool, string) {
	if cfg.Sources.CloudSNI.DataDir == "" {
		return false, "data_dir not set in config"
	}
	return true, ""
}

func (s *CloudSNISource) Run(ctx context.Context, domain string, cfg *config.Config) Result {
	start := time.Now()
	subdomains, err := s.fetch(ctx, domain, cfg)
	dur := time.Since(start)
	if err != nil {
		logger.Errorf("[cloudsni] %v", err)
		return Result{Source: s.Name(), Status: StatusFailed, Err: err, Duration: dur}
	}
	return Result{Source: s.Name(), Subdomains: subdomains, Status: StatusOK, Duration: dur}
}

func (s *CloudSNISource) fetch(ctx context.Context, domain string, cfg *config.Config) ([]string, error) {
	logger.Debugf("[cloudsni] using data_dir=%s proxy=%s", cfg.Sources.CloudSNI.DataDir, cfg.Global.Proxy)

	dataDir := expandHome(cfg.Sources.CloudSNI.DataDir)
	client := buildHTTPClient(cfg.Global.Proxy, cfg.Global.Timeout)

	if err := s.updateIfNeeded(ctx, dataDir, client, cfg.Global.Proxy); err != nil {
		logger.Warningf("[cloudsni] update failed: %v — searching existing data", err)
	}

	return s.search(dataDir, domain)
}

func (s *CloudSNISource) updateIfNeeded(ctx context.Context, dataDir string, client *http.Client, proxy string) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return err
	}

	remoteDates, err := s.fetchRemoteDates(ctx, client, proxy)
	if err != nil {
		return err
	}

	localMeta := s.loadMetadata(dataDir)

	for provider, remoteDate := range remoteDates {
		localDate, ok := localMeta[provider]
		destPath := filepath.Join(dataDir, provider+".txt")

		needsDownload := !ok || localDate != remoteDate
		if _, statErr := os.Stat(destPath); os.IsNotExist(statErr) {
			needsDownload = true
		}

		if !needsDownload {
			logger.Infof("[cloudsni] %s is up to date (%s)", provider, localDate)
			continue
		}
		logger.Infof("[cloudsni] downloading %s...", provider)
		if err := s.downloadFile(ctx, client, cloudSources[provider], destPath, proxy); err != nil {
			logger.Warningf("[cloudsni] failed to download %s: %v", provider, err)
			continue
		}
		localMeta[provider] = remoteDate
		logger.Successf("[cloudsni] %s downloaded", provider)
	}

	return s.saveMetadata(dataDir, localMeta)
}

func (s *CloudSNISource) fetchRemoteDates(ctx context.Context, client *http.Client, proxy string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudIndexURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpdebug.Do(client, req, proxy)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	dates := map[string]string{}
	for provider := range cloudSources {
		pattern := regexp.MustCompile(
			`<div class="flex-1 truncate">\s*` + regexp.QuoteMeta(provider) + `\s*</div>.*?` +
				`<div class="hidden whitespace-nowrap text-right truncate ml-2 w-1/4 sm:block">\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*</div>`,
		)
		m := pattern.FindStringSubmatch(html)
		if m != nil {
			dates[provider] = m[1]
		} else {
			logger.Warningf("[cloudsni] could not find date for %s", provider)
		}
	}
	return dates, nil
}

func (s *CloudSNISource) downloadFile(ctx context.Context, client *http.Client, fileURL, dest, proxy string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return err
	}
	resp, err := httpdebug.Do(client, req, proxy)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func (s *CloudSNISource) loadMetadata(dataDir string) map[string]string {
	path := filepath.Join(dataDir, "update_metadata.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	var meta map[string]string
	if err := json.Unmarshal(data, &meta); err != nil {
		return map[string]string{}
	}
	return meta
}

func (s *CloudSNISource) saveMetadata(dataDir string, meta map[string]string) error {
	path := filepath.Join(dataDir, "update_metadata.json")
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (s *CloudSNISource) search(dataDir, domain string) ([]string, error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("data directory %s not found — run without -s to trigger download", dataDir)
		}
		return nil, err
	}

	searchTerm := "." + domain
	seen := map[string]bool{}
	var results []string

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		fpath := filepath.Join(dataDir, entry.Name())
		f, err := os.Open(fpath)
		if err != nil {
			logger.Warningf("[cloudsni] error reading %s: %v", entry.Name(), err)
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, searchTerm) {
				continue
			}
			var domainsPart string
			if idx := strings.Index(line, "-- "); idx >= 0 {
				domainsPart = line[idx+3:]
			} else {
				domainsPart = line
			}
			for _, token := range strings.Fields(domainsPart) {
				token = strings.Trim(token, "[]")
				if strings.Contains(token, searchTerm) && !seen[token] {
					seen[token] = true
					results = append(results, token)
				}
			}
		}
		f.Close()
	}

	logger.Successf("[cloudsni] found %d subdomains for %s", len(results), domain)
	return results, nil
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

