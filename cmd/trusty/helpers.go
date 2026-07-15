package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/types"
)

var useColor = runtime.GOOS != "windows" && os.Getenv("NO_COLOR") == ""

const (
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
)

func colorize(c, s string) string {
	if !useColor {
		return s
	}
	return c + s + colorReset
}

func colorSeverity(s types.Severity) string {
	switch s {
	case types.SeverityError:
		return colorize(colorRed, "ERROR")
	case types.SeverityWarning:
		return colorize(colorYellow, "WARN")
	case types.SeverityInfo:
		return colorize(colorCyan, "INFO")
	default:
		return "UNKNOWN"
	}
}

func removeTier(tiers []int, t int) []int {
	var out []int
	for _, v := range tiers {
		if v != t {
			out = append(out, v)
		}
	}
	return out
}

func colorScore(score int) string {
	switch {
	case score >= 90:
		return colorize(colorGreen, fmt.Sprintf("%d/100", score))
	case score >= 70:
		return colorize(colorYellow, fmt.Sprintf("%d/100", score))
	default:
		return colorize(colorRed, fmt.Sprintf("%d/100", score))
	}
}

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
