package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/types"
)

func TestLoadPoliciesValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	yamlContent := `
policies:
  - name: no-error
    description: No error severity findings allowed
    condition:
      field: severity
      operator: ">="
      value: 3
    action: fail
    message: Error severity finding detected
  - name: no-security
    description: No security rule violations
    condition:
      field: rule
      operator: "=="
      value: security/hardcoded-credentials
    action: warn
    message: Hardcoded credentials found
`
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadPolicies(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
	if policies[0].Name != "no-error" {
		t.Errorf("expected name 'no-error', got %s", policies[0].Name)
	}
	if policies[0].Action != "fail" {
		t.Errorf("expected action 'fail', got %s", policies[0].Action)
	}
}

func TestParsePoliciesSinglePolicyFallback(t *testing.T) {
	// YAML where "policies" is a scalar triggers PolicySet unmarshal error, falls back to single Policy
	yamlContent := "policies: bad\nname: single-policy\ncondition:\n  field: rule\n  operator: " + `"=="` + "\n  value: x\naction: fail\nmessage: msg\n"
	policies, err := parsePolicies([]byte(yamlContent))
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "single-policy" {
		t.Errorf("expected 'single-policy', got %s", policies[0].Name)
	}
}

func TestLoadPoliciesInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml}}"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadPolicies(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadPoliciesNonExistentFile(t *testing.T) {
	_, err := LoadPolicies("/nonexistent/policy.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !strings.Contains(err.Error(), "reading policies") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEvaluateMatchingFindings(t *testing.T) {
	policies := []Policy{
		{
			Name: "block-critical",
			Condition: Condition{
				Field:    "severity",
				Operator: ">=",
				Value:    3,
			},
			Action:  "fail",
			Message: "Critical severity finding",
		},
	}

	findings := []types.Finding{
		{Rule: "test-rule", Severity: types.SeverityError, Message: "something", Category: "test"},
		{Rule: "other-rule", Severity: types.SeverityInfo, Message: "info", Category: "test"},
	}

	violations := Evaluate(findings, policies)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].PolicyName != "block-critical" {
		t.Errorf("expected policy name 'block-critical', got %s", violations[0].PolicyName)
	}
	if violations[0].Action != "fail" {
		t.Errorf("expected action 'fail', got %s", violations[0].Action)
	}
	if violations[0].Finding.Rule != "test-rule" {
		t.Errorf("expected finding rule 'test-rule', got %s", violations[0].Finding.Rule)
	}
}

func TestEvaluateNonMatchingFindings(t *testing.T) {
	policies := []Policy{
		{
			Name: "block-critical",
			Condition: Condition{
				Field:    "severity",
				Operator: ">=",
				Value:    3,
			},
			Action:  "fail",
			Message: "Critical severity finding",
		},
	}

	findings := []types.Finding{
		{Rule: "test-rule", Severity: types.SeverityInfo, Message: "info", Category: "test"},
	}

	violations := Evaluate(findings, policies)
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(violations))
	}
}

func TestEvaluateRuleMatching(t *testing.T) {
	policies := []Policy{
		{
			Name: "no-hardcoded-creds",
			Condition: Condition{
				Field:    "rule",
				Operator: "==",
				Value:    "security/hardcoded-credentials",
			},
			Action:  "fail",
			Message: "Hardcoded credentials",
		},
	}

	findings := []types.Finding{
		{Rule: "security/hardcoded-credentials", Severity: types.SeverityError, Category: "security"},
		{Rule: "other-rule", Severity: types.SeverityWarning, Category: "other"},
	}

	violations := Evaluate(findings, policies)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Finding.Rule != "security/hardcoded-credentials" {
		t.Errorf("expected rule 'security/hardcoded-credentials', got %s", violations[0].Finding.Rule)
	}
}

func TestEvaluateCategoryMatching(t *testing.T) {
	policies := []Policy{
		{
			Name: "no-security",
			Condition: Condition{
				Field:    "category",
				Operator: "==",
				Value:    "security",
			},
			Action:  "warn",
			Message: "Security issue found",
		},
	}

	findings := []types.Finding{
		{Rule: "sql-injection", Severity: types.SeverityError, Category: "security"},
		{Rule: "bad-style", Severity: types.SeverityInfo, Category: "style"},
	}

	violations := Evaluate(findings, policies)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].PolicyName != "no-security" {
		t.Errorf("expected 'no-security', got %s", violations[0].PolicyName)
	}
	if violations[0].Finding.Category != "security" {
		t.Errorf("expected category 'security', got %s", violations[0].Finding.Category)
	}
}

func TestEvaluateNotEqual(t *testing.T) {
	policies := []Policy{
		{
			Name: "no-info",
			Condition: Condition{
				Field:    "severity",
				Operator: "!=",
				Value:    1,
			},
			Action:  "warn",
			Message: "Non-info finding",
		},
	}

	findings := []types.Finding{
		{Rule: "r1", Severity: types.SeverityWarning, Category: "test"},
		{Rule: "r2", Severity: types.SeverityInfo, Category: "test"},
	}

	violations := Evaluate(findings, policies)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
}

func TestEvaluateMultiplePolicies(t *testing.T) {
	policies := []Policy{
		{
			Name: "no-errors",
			Condition: Condition{Field: "severity", Operator: ">=", Value: 3},
			Action:     "fail",
			Message:    "Error",
		},
		{
			Name: "no-warnings",
			Condition: Condition{Field: "severity", Operator: ">=", Value: 2},
			Action:     "warn",
			Message:    "Warning",
		},
	}

	findings := []types.Finding{
		{Rule: "r1", Severity: types.SeverityError, Category: "test"},
	}

	violations := Evaluate(findings, policies)
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}
}

func TestEvaluateViaOPANotFound(t *testing.T) {
	t.Setenv("OPA_PATH", "/nonexistent/opa-binary")
	findings := []types.Finding{
		{Rule: "test", Severity: types.SeverityWarning, Category: "test"},
	}

	_, err := EvaluateViaOPA("policy.rego", findings)
	if err == nil {
		t.Fatal("expected error when OPA binary not found")
	}
	if !strings.Contains(err.Error(), "opa eval failed") {
		t.Errorf("expected 'opa eval failed' in error, got: %v", err)
	}
}

func TestLoadFromFileValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	minScore := 75
	yamlContent := "scan:\n  min_score: 75\n"
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	pc, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if pc.Scan == nil || pc.Scan.MinScore == nil {
		t.Fatal("expected Scan.MinScore to be set")
	}
	if *pc.Scan.MinScore != minScore {
		t.Errorf("expected min_score 75, got %d", *pc.Scan.MinScore)
	}
}

func TestLoadFromFileInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadFromURLInvalidURL(t *testing.T) {
	_, err := LoadFromURL("ftp://example.com/policy.yaml")
	if err == nil {
		t.Fatal("expected error for invalid URL scheme")
	}
	if !strings.Contains(err.Error(), "invalid policy URL") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestApplyWithNilPolicy(t *testing.T) {
	cfg := &config.Config{}
	Apply(cfg, nil)
}

func TestApplySetsMinScore(t *testing.T) {
	minScore := 80
	pc := &PolicyConfig{
		Scan: &struct {
			MinScore *int `yaml:"min_score"`
		}{
			MinScore: &minScore,
		},
	}

	cfg := &config.Config{}
	Apply(cfg, pc)

	if cfg.Scan.MinScore != 80 {
		t.Errorf("expected MinScore 80, got %d", cfg.Scan.MinScore)
	}
}

func TestApplyNilScan(t *testing.T) {
	pc := &PolicyConfig{Scan: nil}
	cfg := &config.Config{}

	Apply(cfg, pc)
}

func TestMatchConditionGreaterThan(t *testing.T) {
	cond := Condition{Field: "severity", Operator: ">", Value: 2}
	f := types.Finding{Severity: types.SeverityError}
	if !matchCondition(f, cond) {
		t.Error("expected SeverityError (3) > 2 to match")
	}

	f2 := types.Finding{Severity: types.SeverityInfo}
	if matchCondition(f2, cond) {
		t.Error("expected SeverityInfo (1) > 2 to not match")
	}
}

func TestMatchConditionInOperator(t *testing.T) {
	cond := Condition{Field: "rule", Operator: "in", Value: "rule-a,rule-b,rule-c"}
	f := types.Finding{Rule: "rule-b"}
	if !matchCondition(f, cond) {
		t.Error("expected 'rule-b' to be in the list")
	}

	f2 := types.Finding{Rule: "rule-z"}
	if matchCondition(f2, cond) {
		t.Error("expected 'rule-z' to not be in the list")
	}
}

func TestMatchConditionUnknownField(t *testing.T) {
	cond := Condition{Field: "unknown", Operator: "==", Value: "x"}
	f := types.Finding{Severity: types.SeverityError}
	if matchCondition(f, cond) {
		t.Error("expected unknown field to not match")
	}
}
