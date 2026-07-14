package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/WorldOccupier/trusty/internal/types"
)

type Policy struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Condition   Condition `yaml:"condition"`
	Action      string `yaml:"action"`
	Message     string `yaml:"message"`
}

type Condition struct {
	Field    string      `yaml:"field"`
	Operator string      `yaml:"operator"`
	Value    interface{} `yaml:"value"`
}

type Violation struct {
	PolicyName string `json:"policy_name"`
	Message    string `json:"message"`
	Action     string `json:"action"`
	Finding    types.Finding `json:"finding,omitempty"`
}

type PolicySet struct {
	Policies []Policy `yaml:"policies"`
}

func LoadPolicies(path string) ([]Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policies: %w", err)
	}
	return parsePolicies(data)
}

func parsePolicies(data []byte) ([]Policy, error) {
	var set PolicySet
	if err := yaml.Unmarshal(data, &set); err != nil {
		var single Policy
		if err2 := yaml.Unmarshal(data, &single); err2 != nil {
			return nil, fmt.Errorf("parsing policies: %w", err)
		}
		return []Policy{single}, nil
	}
	return set.Policies, nil
}

func Evaluate(findings []types.Finding, policies []Policy) []Violation {
	var violations []Violation
	for _, p := range policies {
		for _, f := range findings {
			if matchCondition(f, p.Condition) {
				violations = append(violations, Violation{
					PolicyName: p.Name,
					Message:    p.Message,
					Action:     p.Action,
					Finding:    f,
				})
			}
		}
	}
	return violations
}

func matchCondition(finding types.Finding, cond Condition) bool {
	var fieldValue interface{}
	switch cond.Field {
	case "severity":
		fieldValue = int(finding.Severity)
	case "rule":
		fieldValue = finding.Rule
	case "category":
		fieldValue = finding.Category
	default:
		return false
	}

	switch cond.Operator {
	case ">=":
		fv, ok1 := toFloat(fieldValue)
		cv, ok2 := toFloat(cond.Value)
		return ok1 && ok2 && fv >= cv
	case ">":
		fv, ok1 := toFloat(fieldValue)
		cv, ok2 := toFloat(cond.Value)
		return ok1 && ok2 && fv > cv
	case "==", "=":
		return fmt.Sprint(fieldValue) == fmt.Sprint(cond.Value)
	case "!=":
		return fmt.Sprint(fieldValue) != fmt.Sprint(cond.Value)
	case "in":
		cvStr := fmt.Sprint(cond.Value)
		fvStr := fmt.Sprint(fieldValue)
		return strings.Contains(cvStr, fvStr)
	}
	return false
}

func toFloat(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	case int32:
		return float64(val), true
	case int64:
		return float64(val), true
	case json.Number:
		f, err := val.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func EvaluateViaOPA(policyPath string, findings []types.Finding) (string, error) {
	opaPath := os.Getenv("OPA_PATH")
	if opaPath == "" {
		opaPath = "opa"
	}

	findingsJSON, err := json.Marshal(findings)
	if err != nil {
		return "", fmt.Errorf("marshaling findings: %w", err)
	}

	input := fmt.Sprintf(`{"findings":%s}`, string(findingsJSON))
	cmd := exec.Command(opaPath, "eval", "--format", "json", "--input", "/dev/stdin", "--data", policyPath, "data.trusty")
	cmd.Stdin = strings.NewReader(input)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("opa eval failed: %w", err)
	}

	return string(output), nil
}
