package config

import (
	"os"
	"path/filepath"
)

const defaultConfigYAML = `# Global settings
global:
  proxy: ""
  retry: 3
  timeout: 120
  concurrency: 1

capsolver:
  token: ""
  proxy: ""

sources:
  shodan:
    api_key: ""

  c99:
    api_key: ""

  crtsh: {}

  securitytrails:
    email: ""
    password: ""

  sourcegraph:
    access_token: ""

  cloudsni:
    data_dir: "~/.cloud-sni-data"

  abuseipdb:
    session_cookie: ""
    use_capsolver: false
`

func WriteDefault(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(defaultConfigYAML), 0600)
}
