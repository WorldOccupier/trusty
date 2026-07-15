package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/types"
)
func runFuzz(cmd *cobra.Command, args []string) error {
	_, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	var files []types.DiffFile

	if cmd.Flags().Changed("dir") || (!staged && from == "" && to == "") {
		goFiles, err := filepath.Glob(filepath.Join(fuzzDir, "*.go"))
		if err != nil || len(goFiles) == 0 {
			fmt.Println(`{"functions":[],"total":0,"files_scanned":0,"errors":0}`)
			return nil
		}
		for _, gf := range goFiles {
			if strings.HasSuffix(gf, "_test.go") || strings.HasSuffix(gf, "_fuzz_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Clean(gf))
			if err != nil {
				continue
			}
			files = append(files, types.DiffFile{
				Path:     gf,
				Language: "go",
				Content:  string(data),
			})
		}
	} else {
		diffOpts := types.DiffOptions{
			Staged: staged,
			From:   from,
			To:     to,
		}
		files, err = scanner.GetDiff(diffOpts)
		if err != nil {
			return fmt.Errorf("getting diff: %w", err)
		}
	}

	if fuzzIterations <= 0 {
		fuzzIterations = 100
	}

	fuzzer := scanner.NewFuzzEngine(fuzzIterations)
	output := fuzzer.Fuzz(files)
	defer fuzzer.Cleanup(files)

	fuzzer.RunTests(files)

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	if output.Errors > 0 {
		return fmt.Errorf("fuzz testing found %d error(s)", output.Errors)
	}

	return nil
}

func runTestGen(cmd *cobra.Command, args []string) error {
	_, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
	}

	files, err := scanner.GetDiff(diffOpts)
	if err != nil {
		return fmt.Errorf("getting diff: %w", err)
	}

	tg := scanner.NewTestGenerator()
	findings, err := tg.GenerateTests(files)
	if err != nil {
		return fmt.Errorf("test generation: %w", err)
	}

	output := map[string]interface{}{
		"results":       findings,
		"total":         len(findings),
		"files_scanned": len(files),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	return nil
}

func runIntent(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if cfg.LLM.APIKey == "" {
		return fmt.Errorf("LLM API key required — set OPENAI_API_KEY or ANTHROPIC_API_KEY")
	}

	llmCfg := llm.ProviderConfig{
		Model:       cfg.LLM.Model,
		Temperature: cfg.LLM.Temperature,
		APIKey:      cfg.LLM.APIKey,
		BaseURL:     cfg.LLM.BaseURL,
	}
	llmProvider := llm.NewProvider(cfg.LLM.Provider, llmCfg)

	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
	}

	files, err := scanner.GetDiff(diffOpts)
	if err != nil {
		return fmt.Errorf("getting diff: %w", err)
	}

	analyzer := scanner.NewIntentAnalyzer(llmProvider)
	results, err := analyzer.Analyze(context.Background(), files, diffOpts)
	if err != nil {
		return fmt.Errorf("intent analysis: %w", err)
	}

	output := map[string]interface{}{
		"results": results,
		"total":   len(results),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	totalIssues := 0
	for _, r := range results {
		totalIssues += len(r.Findings)
	}
	if totalIssues > 0 {
		return fmt.Errorf("found %d intent mismatch(es)", totalIssues)
	}

	return nil
}

func runFingerprint(cmd *cobra.Command, args []string) error {
	var files []types.DiffFile

	if fingerprintAll {
		var goFiles []string
		filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() && strings.HasPrefix(info.Name(), ".") && path != "." {
				return filepath.SkipDir
			}
			if strings.HasSuffix(path, ".go") {
				goFiles = append(goFiles, path)
			}
			return nil
		})
		for _, gf := range goFiles {
			if strings.HasSuffix(gf, "_test.go") || strings.HasSuffix(gf, "_fuzz_test.go") || strings.HasSuffix(gf, "_trusty_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Clean(gf))
			if err != nil {
				continue
			}
			files = append(files, types.DiffFile{
				Path:     gf,
				Language: "go",
				Content:  string(data),
			})
		}
	} else {
		diffOpts := types.DiffOptions{
			Staged: staged,
			From:   from,
			To:     to,
		}
		var err error
		files, err = scanner.GetDiff(diffOpts)
		if err != nil {
			return fmt.Errorf("getting diff: %w", err)
		}
	}

	fp := scanner.NewFingerprinter()
	var results []scanner.FingerprintResult

	for _, f := range files {
		if f.Language != "go" && f.Language != "python" && f.Language != "javascript" && f.Language != "typescript" {
			continue
		}
		result := fp.Analyze(f.Content, f.Path)
		results = append(results, result)
	}

	output := map[string]interface{}{
		"files":  results,
		"total":  len(results),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	return nil
}

