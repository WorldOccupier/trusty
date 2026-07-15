package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/WorldOccupier/trusty/internal/audit"
	"github.com/WorldOccupier/trusty/internal/ci"
	"github.com/WorldOccupier/trusty/internal/hook"
	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/sbom"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/upgrade"
	"github.com/WorldOccupier/trusty/internal/validate"
)
func runInit(cmd *cobra.Command, args []string) error {
	for _, name := range []string{".trusty.yml", ".trusty.yaml"} {
		if _, err := os.Stat(name); err == nil {
			return fmt.Errorf("%s already exists", name)
		}
	}
	def := `# Trusty Configuration
version: 1

scan:
  min_score: 70
  languages:
    - go
    - python
    - typescript

llm:
  provider: openai
  model: gpt-4o
  temperature: 0.1
  # api_key: set via OPENAI_API_KEY or ANTHROPIC_API_KEY

rules:
  hallucination:
    severity: error
  logic_errors:
    severity: warning
  security:
    severity: error

output:
  format: pretty
`
	if err := os.WriteFile(".trusty.yml", []byte(def), 0644); err != nil {
		return fmt.Errorf("writing .trusty.yml: %w", err)
	}
	fmt.Println("Created .trusty.yml")
	return nil
}

func runWatch(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	var llmProvider llm.Provider
	if cfg.LLM.APIKey != "" {
		llmCfg := llm.ProviderConfig{
			Model:       cfg.LLM.Model,
			Temperature: cfg.LLM.Temperature,
			APIKey:      cfg.LLM.APIKey,
			BaseURL:     cfg.LLM.BaseURL,
		}
		llmProvider = llm.NewProvider(cfg.LLM.Provider, llmCfg)
	}

	s := scanner.NewScanner(cfg, llmProvider)

	dirs := args
	w := scanner.NewWatcher(cfg, s, dirs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	return w.Watch(ctx)
}

func runAudit(cmd *cobra.Command, args []string) error {
	limit, _ := cmd.Flags().GetInt("limit")
	status, _ := cmd.Flags().GetString("status")
	since, _ := cmd.Flags().GetString("since")
	asJSON, _ := cmd.Flags().GetBool("json")

	trail := audit.New(".trusty-audit.jsonl")
	entries, err := trail.Query(limit, status, since)
	if err != nil {
		return fmt.Errorf("reading audit trail: %w", err)
	}

	if entries == nil {
		fmt.Println("No audit entries found. Run trusty scan --track first.")
		return nil
	}

	if asJSON {
		data, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("\n%-30s %-20s %-12s %-10s %-8s %s\n",
		"Timestamp", "User", "Command", "Score", "Issues", "Status")
	fmt.Println(strings.Repeat("-", 90))
	for _, e := range entries {
		fmt.Printf("%-30s %-20s %-12s %-10d %-8d %s\n",
			e.Timestamp, e.User, e.Command, e.TrustScore, e.TotalIssues, e.Status)
	}
	fmt.Printf("\n%d entries\n", len(entries))
	return nil
}

func runSBOM(cmd *cobra.Command, args []string) error {
	allMods, _ := cmd.Flags().GetBool("all")
	outPath, _ := cmd.Flags().GetString("output")

	if allMods {
		mods, err := sbom.FindGoMods(".")
		if err != nil {
			return fmt.Errorf("finding go.mod files: %w", err)
		}
		if len(mods) == 0 {
			return fmt.Errorf("no go.mod files found")
		}
		type moduleSBOM struct {
			Path string          `json:"path"`
			BOM  json.RawMessage `json:"bom"`
		}
		var results []moduleSBOM
		for _, mod := range mods {
			data, err := sbom.GenerateGoSBOM(filepath.Dir(mod))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", mod, err)
				continue
			}
			results = append(results, moduleSBOM{
				Path: mod,
				BOM:  data,
			})
		}
		output, _ := json.MarshalIndent(results, "", "  ")
		if outPath != "" {
			return os.WriteFile(filepath.Clean(outPath), output, 0644)
		}
		fmt.Println(string(output))
		return nil
	}

	data, err := sbom.GenerateGoSBOM(".")
	if err != nil {
		data2, err2 := sbom.GenerateFromGoSum("go.sum")
		if err2 != nil {
			return fmt.Errorf("generating SBOM (tried go.mod: %v, go.sum: %v)", err, err2)
		}
		data = data2
	}

	if outPath != "" {
		return os.WriteFile(filepath.Clean(outPath), data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	checkOnly, _ := cmd.Flags().GetBool("check")

	fmt.Printf("Current version: %s\n", upgrade.CurrentVersion())

	release, err := upgrade.CheckLatest()
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	fmt.Printf("Latest version:  %s\n", release.TagName)
	fmt.Printf("Release notes:   %s\n\n", release.HTMLURL)

	if !upgrade.IsNewerAvailable(upgrade.CurrentVersion(), release.TagName) {
		fmt.Println("You're on the latest version.")
		return nil
	}

	if checkOnly {
		fmt.Printf("Update available: %s → %s\n", upgrade.CurrentVersion(), release.TagName)
		fmt.Println("Run 'trusty upgrade' to update.")
		return nil
	}

	fmt.Println("Upgrading...")
	if err := upgrade.PerformUpgrade(release); err != nil {
		return fmt.Errorf("upgrade failed: %w", err)
	}

	fmt.Println("Upgrade complete!")
	return nil
}

func runInstallHook(cmd *cobra.Command, args []string) error {
	hookTypeStr, _ := cmd.Flags().GetString("type")
	force, _ := cmd.Flags().GetBool("force")
	uninstall, _ := cmd.Flags().GetBool("uninstall")

	var t hook.Type
	switch hookTypeStr {
	case "pre-commit":
		t = hook.PreCommit
	case "pre-push":
		t = hook.PrePush
	default:
		return fmt.Errorf("unsupported hook type: %s (use pre-commit or pre-push)", hookTypeStr)
	}

	if uninstall {
		return hook.Uninstall(".", t)
	}
	return hook.Install(".", t, force)
}

func runCI(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	result, err := ci.Run(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("ci pipeline: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Result: %s\n", result.Message)
	if !result.Passed {
		fmt.Fprintf(os.Stderr, "CI pipeline found issues\n")
		os.Exit(1)
	}
	return nil
}

func runValidate(cmd *cobra.Command, args []string) error {
	result := validate.Run(cfgFile)

	for _, c := range result.Checks {
		status := "PASS"
		if !c.Passed {
			status = "FAIL"
		}
		fmt.Printf("[%s] %s", status, c.Name)
		if c.Message != "" {
			fmt.Printf(" — %s", c.Message)
		}
		fmt.Println()
	}

	if !result.Passed {
		fmt.Fprintf(os.Stderr, "%s\n", result.Message)
		os.Exit(1)
	}
	return nil
}

