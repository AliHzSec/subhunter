package helper

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AliHzSec/subhunter/internal/httpdebug"
	"github.com/AliHzSec/subhunter/internal/logger"
)

const capsolverAPI = "https://api.capsolver.com"

type CapsolverClient struct {
	apiKey     string
	proxy      string
	httpClient *http.Client
}

type capsolverSolution struct {
	Cookies   map[string]string `json:"cookies"`
	UserAgent string            `json:"userAgent"`
}

func NewCapsolverClient(apiKey, proxy string) *CapsolverClient {
	// Capsolver API is reached directly — the proxy is only passed inside task
	// payloads so Capsolver uses it when solving the challenge, not for our API calls.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	return &CapsolverClient{
		apiKey: apiKey,
		proxy:  proxy,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// SolveChallenge calls Capsolver AntiCloudflareTask once and returns cf_clearance and userAgent.
// It does not retry internally; callers must retry via their own bounded retry loop.
func (c *CapsolverClient) SolveChallenge(ctx context.Context, targetURL, html string) (cfClearance, userAgent string, err error) {
	logger.Info("Solving Cloudflare challenge...")

	task := map[string]any{
		"type":       "AntiCloudflareTask",
		"websiteURL": targetURL,
		"useragent":  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
	}
	if c.proxy != "" {
		task["proxy"] = formatCapsolverProxy(c.proxy)
	}
	if html != "" {
		task["html"] = html
	}

	payload := map[string]any{
		"clientKey": c.apiKey,
		"task":      task,
	}

	if logger.DebugMode {
		if b, e := json.Marshal(payload); e == nil {
			logger.Debugf("[capsolver] createTask payload: %s", string(b))
		}
	}

	taskID, err := c.createTask(ctx, payload)
	if err != nil {
		return "", "", fmt.Errorf("create capsolver task: %w", err)
	}
	if taskID == "" {
		return "", "", fmt.Errorf("capsolver returned empty task ID")
	}
	logger.Infof("Capsolver task created: %s", taskID)

	solution, err := c.pollResult(ctx, taskID)
	if err != nil {
		return "", "", fmt.Errorf("capsolver polling: %w", err)
	}

	cfClearance = solution.Cookies["cf_clearance"]
	if cfClearance == "" {
		return "", "", fmt.Errorf("no cf_clearance in Capsolver solution")
	}

	if logger.DebugMode {
		logger.Debugf("[capsolver] solution cf_clearance (full): %s", cfClearance)
		logger.Debugf("[capsolver] solution userAgent: %s", solution.UserAgent)
	}

	n := len(cfClearance)
	if n > 50 {
		n = 50
	}
	logger.Successf("cf_clearance obtained: %s...", cfClearance[:n])
	return cfClearance, solution.UserAgent, nil
}

func (c *CapsolverClient) createTask(ctx context.Context, payload map[string]any) (string, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, capsolverAPI+"/createTask", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// Capsolver API is called directly (no proxy); httpdebug logs the full exchange.
	resp, err := httpdebug.Do(c.httpClient, req, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		TaskID  string `json:"taskId"`
		ErrorID int    `json:"errorId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.ErrorID != 0 {
		return "", fmt.Errorf("capsolver error id %d", result.ErrorID)
	}
	return result.TaskID, nil
}

func (c *CapsolverClient) pollResult(ctx context.Context, taskID string) (*capsolverSolution, error) {
	payload := map[string]string{
		"clientKey": c.apiKey,
		"taskId":    taskID,
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}

		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, capsolverAPI+"/getTaskResult", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpdebug.Do(c.httpClient, req, "")
		if err != nil {
			return nil, err
		}

		var result struct {
			Status   string             `json:"status"`
			ErrorID  int                `json:"errorId"`
			Solution *capsolverSolution `json:"solution"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		if result.Status == "ready" {
			logger.Success("Cloudflare challenge solved!")
			return result.Solution, nil
		}
		if result.Status == "failed" || result.ErrorID != 0 {
			return nil, fmt.Errorf("capsolver task failed (status=%s errorId=%d)", result.Status, result.ErrorID)
		}
	}
}

// formatCapsolverProxy converts http://user:pass@host:port to host:port:user:pass,
// URL-encoding the username and password to match what the Capsolver API expects.
func formatCapsolverProxy(proxy string) string {
	u, err := url.Parse(proxy)
	if err != nil {
		return proxy
	}
	host := u.Hostname()
	port := u.Port()
	if u.User != nil {
		user := url.QueryEscape(u.User.Username())
		pass, _ := u.User.Password()
		return strings.Join([]string{host, port, user, url.QueryEscape(pass)}, ":")
	}
	return host + ":" + port
}
