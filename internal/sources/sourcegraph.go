package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/AliHzSec/subhunter/internal/config"
	"github.com/AliHzSec/subhunter/internal/httpdebug"
	"github.com/AliHzSec/subhunter/internal/logger"
)

const sgAPIURL = "https://sourcegraph.com/.api/graphql"

const sgGQLQuery = `
query Search($q: String!) {
  search(query: $q, version: V3) {
    results {
      results {
        ... on FileMatch {
          repository {
            name
          }
          file {
            path
          }
          lineMatches {
            preview
          }
        }
      }
    }
  }
}`

type SourcegraphSource struct{}

func (s *SourcegraphSource) Name() string { return "sourcegraph" }

func (s *SourcegraphSource) ConfigCheck(cfg *config.Config) (bool, string) {
	if cfg.Sources.Sourcegraph.AccessToken == "" {
		return false, "access_token not set in config"
	}
	return true, ""
}

func (s *SourcegraphSource) Run(ctx context.Context, domain string, cfg *config.Config) Result {
	start := time.Now()
	subdomains, err := s.fetch(ctx, domain, cfg)
	dur := time.Since(start)
	if err != nil {
		logger.Errorf("[sourcegraph] %v", err)
		return Result{Source: s.Name(), Status: StatusFailed, Err: err, Duration: dur}
	}
	return Result{Source: s.Name(), Subdomains: subdomains, Status: StatusOK, Duration: dur}
}

type sgGraphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type sgGraphQLResponse struct {
	Data struct {
		Search struct {
			Results struct {
				Results []struct {
					Repository struct {
						Name string `json:"name"`
					} `json:"repository"`
					File struct {
						Path string `json:"path"`
					} `json:"file"`
					LineMatches []struct {
						Preview string `json:"preview"`
					} `json:"lineMatches"`
				} `json:"results"`
			} `json:"results"`
		} `json:"search"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (s *SourcegraphSource) fetch(ctx context.Context, domain string, cfg *config.Config) ([]string, error) {
	logger.Debugf("[sourcegraph] using access_token=%s proxy=%s", cfg.Sources.Sourcegraph.AccessToken, cfg.Global.Proxy)

	client := buildHTTPClient(cfg.Global.Proxy, cfg.Global.Timeout)

	subdomainPattern := regexp.MustCompile(`(?i)([a-zA-Z0-9\-]+\.)+` + regexp.QuoteMeta(domain))
	ipPattern := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	seen := map[string]bool{}
	var results []string

	escapedDomain := strings.ReplaceAll(regexp.QuoteMeta(domain), `\.`, `\.`)
	searchQuery := fmt.Sprintf(
		`/([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.%s\b/ count:all fork:yes archived:yes patterntype:regexp`,
		escapedDomain,
	)

	logger.Infof("[sourcegraph] querying GraphQL API for subdomains of %s...", domain)

	texts, err := s.doSearch(ctx, client, cfg.Sources.Sourcegraph.AccessToken, cfg.Global.Proxy, searchQuery)
	if err != nil {
		return nil, err
	}

	for _, text := range texts {
		for _, m := range subdomainPattern.FindAllString(text, -1) {
			candidate := strings.ToLower(m)
			if ipPattern.MatchString(candidate) {
				continue
			}
			if !strings.HasSuffix(candidate, "."+domain) {
				continue
			}
			if !seen[candidate] {
				seen[candidate] = true
				results = append(results, candidate)
			}
		}
	}

	logger.Successf("[sourcegraph] found %d subdomains for %s", len(results), domain)
	return results, nil
}

func (s *SourcegraphSource) doSearch(ctx context.Context, client *http.Client, token, proxy, query string) (texts []string, err error) {
	payload, err := json.Marshal(sgGraphQLRequest{
		Query:     sgGQLQuery,
		Variables: map[string]any{"q": query},
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sgAPIURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpdebug.Do(client, req, proxy)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid access token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var gqlResp sgGraphQLResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return nil, fmt.Errorf("JSON decode error: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		msgs := make([]string, len(gqlResp.Errors))
		for i, e := range gqlResp.Errors {
			msgs[i] = e.Message
		}
		return nil, fmt.Errorf("GraphQL errors: %s", strings.Join(msgs, "; "))
	}

	for _, match := range gqlResp.Data.Search.Results.Results {
		texts = append(texts, match.Repository.Name)
		texts = append(texts, match.File.Path)
		for _, lm := range match.LineMatches {
			texts = append(texts, lm.Preview)
		}
	}

	return texts, nil
}
