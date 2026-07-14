package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

type VerificationEngine struct{}

func NewVerificationEngine() *VerificationEngine {
	return &VerificationEngine{}
}

func (v *VerificationEngine) Verify(ctx context.Context, files []types.DiffFile) ([]types.Finding, error) {
	var findings []types.Finding

	for _, file := range files {
		if file.Language != "go" {
			continue
		}

		fs := v.checkFunctionSignatures(file.Content, file.Diff)
		for i := range fs {
			fs[i].Category = file.Path
		}
		findings = append(findings, fs...)

		es := v.checkErrorHandling(file.Content)
		for i := range es {
			es[i].Category = file.Path
		}
		findings = append(findings, es...)
	}

	return findings, nil
}

func (v *VerificationEngine) checkFunctionSignatures(content, diff string) []types.Finding {
	var findings []types.Finding

	funcPattern := regexp.MustCompile(`func\s+(\w+)\s*\(([^)]*)\)\s*([^(]*)`)
	matches := funcPattern.FindAllStringSubmatch(content, -1)

	seen := make(map[string]bool)

	for _, m := range matches {
		name := m[1]
		params := m[2]
		returns := strings.TrimSpace(m[3])

		if seen[name] {
			continue
		}
		seen[name] = true

		if isFetchLike(name) && returnsError(returns) {
			if !strings.Contains(params, "ctx") && !strings.Contains(params, "context") {
				findings = append(findings, types.Finding{
					Rule:       "missing-context",
					Severity:   types.SeverityWarning,
					Message:    fmt.Sprintf("Function '%s' returns error but doesn't accept context.Context", name),
					Suggestion: "Add context.Context parameter for cancellation and deadline support",
					Category:   "verification",
				})
			}
		}

		if isWriteLike(name) && strings.Contains(params, "string") {
			if !strings.Contains(content, "sanitize") && !strings.Contains(content, "Validate") && !strings.Contains(content, "validate") {
				findings = append(findings, types.Finding{
					Rule:       "missing-input-validation",
					Severity:   types.SeverityInfo,
					Message:    fmt.Sprintf("Function '%s' accepts string parameters but no input validation found", name),
					Suggestion: "Consider adding input validation for string parameters",
					Category:   "verification",
				})
			}
		}
	}

	return findings
}

func isFetchLike(name string) bool {
	prefixes := []string{"get", "fetch", "load", "query", "find", "list"}
	for _, p := range prefixes {
		if strings.HasPrefix(strings.ToLower(name), p) {
			return true
		}
	}
	return false
}

func isWriteLike(name string) bool {
	prefixes := []string{"save", "create", "update", "insert", "store", "write", "set"}
	for _, p := range prefixes {
		if strings.HasPrefix(strings.ToLower(name), p) {
			return true
		}
	}
	return false
}

func returnsError(returns string) bool {
	clean := strings.TrimSpace(returns)
	clean = strings.TrimPrefix(clean, "(")
	clean = strings.TrimSuffix(clean, ")")
	clean = strings.TrimSpace(clean)

	if clean == "" {
		return false
	}

	parts := strings.Split(clean, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "error" || strings.HasPrefix(p, "error") || p == "error)" {
			return true
		}
	}
	return false
}

func (v *VerificationEngine) checkErrorHandling(content string) []types.Finding {
	var findings []types.Finding
	seen := make(map[int]map[string]bool)

	errorReturningFuncs := []string{
		".Close()", ".Write(", ".Read(", ".Sync()",
		"json.Unmarshal", "json.Marshal",
		"os.Create", "os.Open", "os.ReadFile", "os.WriteFile",
		"ioutil.ReadFile", "ioutil.WriteFile",
		"net/http.Get", "net/http.Post",
		"db.Query", "db.Exec", "db.Prepare",
		"rows.Scan", "rows.Close",
		"ctx.Err()",
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.HasPrefix(trimmed, "\"") || strings.HasPrefix(trimmed, "`") {
			continue
		}
		if isShortVarDecl(trimmed) {
			continue
		}
		if strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "_ =") {
			continue
		}

		if seen[i] == nil {
			seen[i] = make(map[string]bool)
		}

		for _, funcName := range errorReturningFuncs {
			if !strings.Contains(trimmed, funcName) {
				continue
			}
			if seen[i][funcName] {
				continue
			}
			seen[i][funcName] = true

			nextLine := ""
			if i+1 < len(lines) {
				nextLine = strings.TrimSpace(lines[i+1])
			}
			if strings.HasPrefix(nextLine, "if err") {
				continue
			}

			findings = append(findings, types.Finding{
				Rule:       "unchecked-error",
				Severity:   types.SeverityError,
				Message:    fmt.Sprintf("Unchecked error return from %s", funcName),
				Line:       i + 1,
				Suggestion: "Handle the error: check it or explicitly ignore with _ =",
				Category:   "verification",
			})
		}

		flaggedOnLine := len(seen[i]) > 0
		if !flaggedOnLine {
			errorPattern := regexp.MustCompile(`\.(\w+)\(`)
			calls := errorPattern.FindAllStringSubmatch(trimmed, -1)
			for _, call := range calls {
				methodName := call[1]
				if isKnownErrorReturn(methodName) && !seen[i][methodName] {
					seen[i][methodName] = true
					findings = append(findings, types.Finding{
						Rule:       "unchecked-error",
						Severity:   types.SeverityError,
						Message:    fmt.Sprintf("Unchecked error return from '%s' call", methodName),
						Line:       i + 1,
						Suggestion: "Handle the error return value",
						Category:   "verification",
					})
				}
			}
		}
	}

	return findings
}

func isShortVarDecl(line string) bool {
	return strings.Contains(line, ":=") || strings.Contains(line, "= true") || strings.Contains(line, "= false") ||
		strings.Contains(line, "= nil") || strings.Contains(line, "= 0") || strings.Contains(line, "= \"")
}

func isKnownErrorReturn(method string) bool {
	known := map[string]bool{
		"Close": true, "Write": true, "Read": true, "Sync": true,
		"Flush": true, "Commit": true, "Rollback": true,
	}
	return known[method]
}
