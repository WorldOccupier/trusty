package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version int    `yaml:"version"`
	Scan    Scan   `yaml:"scan"`
	LLM     LLM    `yaml:"llm"`
	Rules   Rules  `yaml:"rules"`
	Output  Output `yaml:"output"`
}

type Scan struct {
	Tiers     []int    `yaml:"tiers"`
	MinScore  int      `yaml:"min_score"`
	Languages []string `yaml:"languages"`
}

type LLM struct {
	Provider    string  `yaml:"provider"`
	Model       string  `yaml:"model"`
	Temperature float64 `yaml:"temperature"`
	APIKey      string  `yaml:"api_key"`
	BaseURL     string  `yaml:"base_url"`
}

type Rules struct {
	Hallucination RuleConfig `yaml:"hallucination"`
	LogicErrors   RuleConfig `yaml:"logic_errors"`
	Security      RuleConfig `yaml:"security"`
}

type RuleConfig struct {
	Severity string `yaml:"severity"`
}

type Output struct {
	Format  string `yaml:"format"`
	CIMode  bool   `yaml:"ci_mode"`
	OutFile string `yaml:"out_file"`
}

func Default() *Config {
	return &Config{
		Version: 1,
		Scan: Scan{
			Tiers:     []int{1, 2, 3},
			MinScore:  70,
			Languages: []string{"go", "python", "typescript"},
		},
		LLM: LLM{
			Provider:    "openai",
			Model:       "gpt-4o",
			Temperature: 0.1,
			APIKey:      os.Getenv("OPENAI_API_KEY"),
			BaseURL:     "https://api.openai.com/v1",
		},
		Rules: Rules{
			Hallucination: RuleConfig{Severity: "error"},
			LogicErrors:   RuleConfig{Severity: "warning"},
			Security:      RuleConfig{Severity: "error"},
		},
		Output: Output{
			Format: "pretty",
			CIMode: os.Getenv("CI") == "true",
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if os.Getenv("OPENAI_API_KEY") != "" {
		cfg.LLM.APIKey = os.Getenv("OPENAI_API_KEY")
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" && cfg.LLM.Provider == "anthropic" {
		cfg.LLM.APIKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	return cfg, nil
}
