package policy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/WorldOccupier/trusty/internal/config"
)

type PolicyConfig struct {
	Scan *struct {
		MinScore *int `yaml:"min_score"`
	} `yaml:"scan"`
}

func LoadFromFile(path string) (*PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return parsePolicy(data)
}

func LoadFromURL(url string) (*PolicyConfig, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("invalid policy URL: %s", url)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching policy: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading policy response: %w", err)
	}

	return parsePolicy(data)
}

func parsePolicy(data []byte) (*PolicyConfig, error) {
	var p PolicyConfig
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}
	return &p, nil
}

func Apply(cfg *config.Config, p *PolicyConfig) {
	if p == nil {
		return
	}
	if p.Scan != nil && p.Scan.MinScore != nil {
		cfg.Scan.MinScore = *p.Scan.MinScore
	}
}
