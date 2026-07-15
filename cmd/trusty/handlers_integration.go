package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"github.com/WorldOccupier/trusty/internal/compare"
	"github.com/WorldOccupier/trusty/internal/dashboard"
	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/fixer"
	"github.com/WorldOccupier/trusty/internal/jira"
	"github.com/WorldOccupier/trusty/internal/merge"
	"github.com/WorldOccupier/trusty/internal/mrcomment"
	"github.com/WorldOccupier/trusty/internal/policy"
	"github.com/WorldOccupier/trusty/internal/prcomment"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/server"
	"github.com/WorldOccupier/trusty/internal/slack"
	"github.com/WorldOccupier/trusty/internal/sso"
	"github.com/WorldOccupier/trusty/internal/tui"
	"github.com/WorldOccupier/trusty/internal/types"
)
func runPRComment(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trusty pr-comment <scan-result.json>")
	}

	data, err := os.ReadFile(filepath.Clean(args[0]))
	if err != nil {
		return fmt.Errorf("reading scan result: %w", err)
	}

	client := prcomment.New()
	body := prcomment.BuildCommentBody(data)

	if err := client.Post(body); err != nil {
		return fmt.Errorf("posting PR comment: %w", err)
	}

	fmt.Println("PR comment posted successfully.")
	return nil
}

func runTUI(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return tui.RunFromFile(args[0])
	}

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

	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
		Base:   base,
		Head:   head,
	}

	return tui.Run(s, diffOpts)
}

func runPolicyCheck(cmd *cobra.Command, args []string) error {
	policyPath, _ := cmd.Flags().GetString("policy")
	inputPath, _ := cmd.Flags().GetString("input")
	useOPA, _ := cmd.Flags().GetBool("opa")

	var findings []types.Finding

	if inputPath != "" {
		data, err := os.ReadFile(filepath.Clean(inputPath))
		if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}
		var scanResult types.ScanResult
		if err := json.Unmarshal(data, &scanResult); err != nil {
			var findingsOnly []types.Finding
			if err2 := json.Unmarshal(data, &findingsOnly); err2 != nil {
				return fmt.Errorf("parsing input (tried result: %v, findings: %v)", err, err2)
			}
			findings = findingsOnly
		} else {
			for _, f := range scanResult.Files {
				findings = append(findings, f.Findings...)
			}
		}
	} else {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		s := scanner.NewScanner(cfg, nil)
		diffOpts := types.DiffOptions{Staged: staged, From: from, To: to, Base: base, Head: head}
		result, err := s.Scan(context.Background(), diffOpts)
		s.FlushCache()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
		for _, f := range result.Files {
			findings = append(findings, f.Findings...)
		}
	}

	if useOPA {
		result, err := policy.EvaluateViaOPA(policyPath, findings)
		if err != nil {
			return fmt.Errorf("OPA evaluation: %w", err)
		}
		fmt.Println(result)
		return nil
	}

	policies, err := policy.LoadPolicies(policyPath)
	if err != nil {
		policies, err = policy.LoadPolicies("policy.yml")
		if err != nil {
			return fmt.Errorf("loading policies from %s (tried policy.yml): %w", policyPath, err)
		}
	}

	violations := policy.Evaluate(findings, policies)
	output := map[string]interface{}{
		"findings_count":   len(findings),
		"policies_count":   len(policies),
		"violations_count": len(violations),
		"violations":       violations,
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	if len(violations) > 0 {
		return fmt.Errorf("found %d policy violation(s)", len(violations))
	}
	return nil
}

func runDashboard(cmd *cobra.Command, args []string) error {
	outPath, _ := cmd.Flags().GetString("output")
	asJSON, _ := cmd.Flags().GetBool("json")

	if asJSON {
		data, err := dashboard.WriteJSON(".trusty-audit.jsonl")
		if err != nil {
			return fmt.Errorf("generating dashboard JSON: %w", err)
		}
		fmt.Println(data)
		return nil
	}

	if err := dashboard.WriteToFile(".trusty-audit.jsonl", outPath); err != nil {
		return fmt.Errorf("generating dashboard: %w", err)
	}

	fmt.Printf("Dashboard written to %s\n", outPath)
	return nil
}

func runFix(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trusty fix <scan-result.json> [--dry-run] [--interactive]")
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	interactive, _ := cmd.Flags().GetBool("interactive")
	dir, _ := cmd.Flags().GetString("dir")

	f := fixer.New()
	f.DryRun = dryRun
	f.Interactive = interactive

	return f.ApplyResultFile(args[0], dir)
}

func runCompare(cmd *cobra.Command, args []string) error {
	asJSON, _ := cmd.Flags().GetBool("json")

	baseline, err := compare.LoadResult(args[0])
	if err != nil {
		return err
	}
	current, err := compare.LoadResult(args[1])
	if err != nil {
		return err
	}

	result := compare.Compare(baseline, current)

	if asJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	compare.PrintTable(result)

	if len(result.NewFindings) > 0 {
		return fmt.Errorf("found %d new finding(s) compared to baseline", len(result.NewFindings))
	}
	return nil
}

func runMerge(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if minScore > 0 {
		cfg.Scan.MinScore = minScore
	}

	result, err := merge.Run(context.Background(), cfg, policyFile, trackRegression)
	if err != nil {
		return fmt.Errorf("merge gate: %w", err)
	}

	if result.Details != nil && result.Details.ScanResult != nil {
		r := result.Details.ScanResult
		fmt.Fprintf(os.Stderr, "Trust score: %d/100 | Issues: %d\n", r.TrustScore, r.Summary.TotalIssues)

		for _, f := range r.Files {
			for _, finding := range f.Findings {
				sev := "INFO"
				switch finding.Severity {
				case types.SeverityError:
					sev = "ERROR"
				case types.SeverityWarning:
					sev = "WARN"
				}
				fmt.Fprintf(os.Stderr, "  [%s] %s:%d %s\n", sev, f.Path, finding.Line, finding.Message)
			}
		}

		if len(result.Details.PolicyViolations) > 0 {
			fmt.Fprintf(os.Stderr, "Policy violations: %d\n", len(result.Details.PolicyViolations))
			for _, v := range result.Details.PolicyViolations {
				fmt.Fprintf(os.Stderr, "  [%s] %s\n", v.Action, v.Message)
			}
		}

		if result.Details.RegressionMessage != "" {
			fmt.Fprintf(os.Stderr, "Regression: %s\n", result.Details.RegressionMessage)
		}
	}

	if result.Passed {
		fmt.Println(result.Message)
		return nil
	}

	fmt.Fprintf(os.Stderr, "%s\n", result.Message)
	os.Exit(1)
	return nil
}

func runWeb(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	enableSSO, _ := cmd.Flags().GetBool("sso")
	ssoConfigPath, _ := cmd.Flags().GetString("sso-config")

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	srv := server.New(cfg, port)

	if enableSSO {
		ssoCfg := sso.Config{}
		if ssoConfigPath != "" {
			data, err := os.ReadFile(filepath.Clean(ssoConfigPath))
			if err != nil {
				return fmt.Errorf("reading SSO config: %w", err)
			}
			if err := yaml.Unmarshal(data, &ssoCfg); err != nil {
				return fmt.Errorf("parsing SSO config: %w", err)
			}
		}
		srv.SetSSO(sso.New(ssoCfg))
	}

	return srv.Start()
}

func runSlack(cmd *cobra.Command, args []string) error {
	webhookURL, _ := cmd.Flags().GetString("webhook-url")

	result, err := loadScanResult(args[0])
	if err != nil {
		return err
	}

	client := slack.New(webhookURL)
	if err := client.Post(result); err != nil {
		return fmt.Errorf("posting to Slack: %w", err)
	}

	fmt.Println("Scan results posted to Slack successfully.")
	return nil
}

func runJira(cmd *cobra.Command, args []string) error {
	project, _ := cmd.Flags().GetString("project")

	result, err := loadScanResult(args[0])
	if err != nil {
		return err
	}

	client := jira.New()
	if project != "" {
		os.Setenv("JIRA_PROJECT", project)
	}

	keys, err := client.CreateIssues(result)
	if err != nil {
		return fmt.Errorf("creating Jira issues: %w", err)
	}

	if len(keys) == 0 {
		fmt.Println("No issues created (no findings found).")
		return nil
	}

	fmt.Printf("Created %d Jira issue(s):\n", len(keys))
	for _, key := range keys {
		fmt.Printf("  %s\n", key)
	}
	return nil
}

func runMRComment(cmd *cobra.Command, args []string) error {
	result, err := loadScanResult(args[0])
	if err != nil {
		return err
	}

	client := mrcomment.New()
	if err := client.Post(result); err != nil {
		return fmt.Errorf("posting MR comment: %w", err)
	}

	fmt.Println("MR comment posted successfully.")
	return nil
}

