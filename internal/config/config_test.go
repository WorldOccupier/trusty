package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
	if cfg.Scan.MinScore != 70 {
		t.Errorf("MinScore = %d, want 70", cfg.Scan.MinScore)
	}
	if cfg.LLM.Provider != "openai" {
		t.Errorf("LLM Provider = %q, want openai", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "gpt-4o" {
		t.Errorf("LLM Model = %q, want gpt-4o", cfg.LLM.Model)
	}
	if cfg.Rules.Hallucination.Severity != "error" {
		t.Errorf("Hallucination severity = %q, want error", cfg.Rules.Hallucination.Severity)
	}
	if cfg.Output.Format != "pretty" {
		t.Errorf("Output format = %q, want pretty", cfg.Output.Format)
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/.trusty.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Scan.MinScore != 70 {
		t.Errorf("MinScore = %d, want 70", cfg.Scan.MinScore)
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	content := []byte(`version: 1
scan:
  min_score: 85
  languages: [go]
llm:
  provider: anthropic
  model: claude-3
rules:
  security:
    severity: warning
output:
  format: json
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Scan.MinScore != 85 {
		t.Errorf("MinScore = %d, want 85", cfg.Scan.MinScore)
	}
	if cfg.LLM.Provider != "anthropic" {
		t.Errorf("LLM Provider = %q, want anthropic", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "claude-3" {
		t.Errorf("LLM Model = %q, want claude-3", cfg.LLM.Model)
	}
	if cfg.Rules.Security.Severity != "warning" {
		t.Errorf("Security severity = %q, want warning", cfg.Rules.Security.Severity)
	}
	if cfg.Output.Format != "json" {
		t.Errorf("Output format = %q, want json", cfg.Output.Format)
	}
}

func TestLoad_WithAPIKeyEnv(t *testing.T) {
	os.Setenv("OPENAI_API_KEY", "test-key-12345")
	defer os.Unsetenv("OPENAI_API_KEY")

	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	content := []byte(`version: 1
llm:
  provider: openai
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LLM.APIKey != "test-key-12345" {
		t.Errorf("APIKey = %q, want test-key-12345", cfg.LLM.APIKey)
	}
}

func TestLoad_WithAnthropicEnv(t *testing.T) {
	os.Setenv("ANTHROPIC_API_KEY", "ant-key-12345")
	defer os.Unsetenv("ANTHROPIC_API_KEY")

	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	content := []byte(`version: 1
llm:
  provider: anthropic
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LLM.APIKey != "ant-key-12345" {
		t.Errorf("APIKey = %q, want ant-key-12345", cfg.LLM.APIKey)
	}
	if cfg.LLM.Provider != "anthropic" {
		t.Errorf("Provider = %q, want anthropic", cfg.LLM.Provider)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	content := []byte(`invalid: yaml: : :`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoad_PartialConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	content := []byte(`version: 1
scan:
  min_score: 90
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Scan.MinScore != 90 {
		t.Errorf("MinScore = %d, want 90", cfg.Scan.MinScore)
	}
	if cfg.LLM.Provider != "openai" {
		t.Errorf("LLM Provider = %q, want openai (default)", cfg.LLM.Provider)
	}
	if cfg.Rules.Hallucination.Severity != "error" {
		t.Errorf("Hallucination severity = %q, want error (default)", cfg.Rules.Hallucination.Severity)
	}
}
