package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/types"
)

func severityStr(s types.Severity) string {
	switch s {
	case types.SeverityError:
		return "ERROR"
	case types.SeverityWarning:
		return "WARN"
	case types.SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

func severityFromString(s string) types.Severity {
	switch s {
	case "error":
		return types.SeverityError
	case "warning", "warn":
		return types.SeverityWarning
	case "info":
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

func severityFromConfig(s string) types.Severity {
	return severityFromString(s)
}

func filterBySeverity(findings []types.Finding, minSev types.Severity) []types.Finding {
	if minSev <= types.SeverityInfo {
		return findings
	}
	var filtered []types.Finding
	for _, f := range findings {
		if f.Severity >= minSev {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func writeOutput(data []byte, path string) error {
	if path == "" {
		fmt.Println(string(data))
		return nil
	}
	return os.WriteFile(filepath.Clean(path), data, 0644)
}

func loadConfig() (*config.Config, error) {
	if cfgFile != "" {
		return config.Load(cfgFile)
	}
	return config.Default(), nil
}

func loadScanResult(path string) (*types.ScanResult, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var result types.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing scan result: %w", err)
	}

	return &result, nil
}
