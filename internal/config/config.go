package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Global    GlobalConfig    `yaml:"global"`
	Capsolver CapsolverConfig `yaml:"capsolver"`
	Sources   SourcesConfig   `yaml:"sources"`
}

type GlobalConfig struct {
	Proxy       string `yaml:"proxy"`
	Retry       int    `yaml:"retry"`
	Timeout     int    `yaml:"timeout"`
	Concurrency int    `yaml:"concurrency"`
}

type CapsolverConfig struct {
	Token string `yaml:"token"`
	Proxy string `yaml:"proxy"`
}

type SourcesConfig struct {
	Shodan         ShodanConfig         `yaml:"shodan"`
	C99            C99Config            `yaml:"c99"`
	SecurityTrails SecurityTrailsConfig `yaml:"securitytrails"`
	Sourcegraph    SourcegraphConfig    `yaml:"sourcegraph"`
	CloudSNI       CloudSNIConfig       `yaml:"cloudsni"`
	AbuseIPDB      AbuseIPDBConfig      `yaml:"abuseipdb"`
}

type ShodanConfig struct {
	APIKey string `yaml:"api_key"`
}

type C99Config struct {
	APIKey string `yaml:"api_key"`
}

type SecurityTrailsConfig struct {
	Email    string `yaml:"email"`
	Password string `yaml:"password"`
}

type SourcegraphConfig struct {
	AccessToken string `yaml:"access_token"`
}

type CloudSNIConfig struct {
	DataDir string `yaml:"data_dir"`
}

type AbuseIPDBConfig struct {
	SessionCookie string `yaml:"session_cookie"`
	UseCapsolver  bool   `yaml:"use_capsolver"`
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.config/subhunter/provider-config.yaml"
	}
	return filepath.Join(home, ".config", "subhunter", "provider-config.yaml")
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Global.Retry == 0 {
		cfg.Global.Retry = 3
	}
	if cfg.Global.Timeout == 0 {
		cfg.Global.Timeout = 120
	}
	if cfg.Global.Concurrency == 0 {
		cfg.Global.Concurrency = 1
	}
	if cfg.Sources.CloudSNI.DataDir == "" {
		home, _ := os.UserHomeDir()
		cfg.Sources.CloudSNI.DataDir = filepath.Join(home, ".cloud-sni-data")
	}
	return &cfg, nil
}
