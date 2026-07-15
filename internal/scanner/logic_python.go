package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

func (d *LogicDetector) detectPythonDeep(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "assert ") {
			findings = append(findings, types.Finding{
				Rule:       "assert-used",
				Severity:   types.SeverityWarning,
				Message:    "assert statement will be removed with -O flag — not suitable for production validation",
				Line:       i + 1,
				Suggestion: "Use proper if/raise instead of assert for production checks",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "is ") && strings.Contains(trimmed, "True") {
			if strings.Contains(trimmed, "if ") || strings.Contains(trimmed, "elif ") || strings.Contains(trimmed, "while ") {
				if strings.Contains(trimmed, "is True") || strings.Contains(trimmed, "is False") {
					findings = append(findings, types.Finding{
						Rule:       "is-comparison-literal",
						Severity:   types.SeverityInfo,
						Message:    "Use 'if x:' instead of 'if x is True:', use '==' for value comparison",
						Line:       i + 1,
						Suggestion: "Replace 'is True' with direct boolean evaluation",
						Category:   path,
					})
				}
			}
		}

		if strings.Contains(trimmed, "except ") && strings.Contains(trimmed, "Exception") {
			if !strings.Contains(trimmed, "as ") {
				findings = append(findings, types.Finding{
					Rule:       "bare-exception-catch",
					Severity:   types.SeverityInfo,
					Message:    "Catching Exception without binding to a variable — exception details lost",
					Line:       i + 1,
					Suggestion: "Add 'as e' to capture exception details",
					Category:   path,
				})
			}
		}

		if matched, _ := regexp.MatchString(`^\s*return\s+True\s+if\s+`, trimmed); matched {
			findings = append(findings, types.Finding{
				Rule:       "ternary-return-boolean",
				Severity:   types.SeverityInfo,
				Message:    "Redundant ternary: 'return True if cond else False' simplifies to 'return cond'",
				Line:       i + 1,
				Suggestion: "Simplify to 'return <condition>' directly",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "while True:") {
			hasBreak := false
			for j := i + 1; j < len(lines) && j < i+30; j++ {
				nl := strings.TrimSpace(lines[j])
				if nl == "break" || strings.HasPrefix(nl, "return") {
					hasBreak = true
					break
				}
				if nl == "" {
					continue
				}
				indent := len(lines[j]) - len(strings.TrimLeft(lines[j], " \t"))
				if indent == 0 && nl != "" {
					break
				}
			}
			if !hasBreak {
				findings = append(findings, types.Finding{
					Rule:       "infinite-loop",
					Severity:   types.SeverityError,
					Message:    "Infinite while True loop without break or return within 30 lines",
					Line:       i + 1,
					Suggestion: "Add a break condition or return statement",
					Category:   path,
				})
			}
		}

		defMatch := regexp.MustCompile(`def (\w+)\(.*,\s*(\w+\s*=\s*(\{\}|\[\]|""|datetime\.now))`).FindStringSubmatch(trimmed)
		if len(defMatch) > 2 {
			findings = append(findings, types.Finding{
				Rule:       "mutable-default-arg",
				Severity:   types.SeverityError,
				Message:    fmt.Sprintf("Mutable default argument in %s: %s — all calls share the same object", defMatch[1], defMatch[2]),
				Line:       i + 1,
				Suggestion: "Use None as default and create a new instance inside the function body",
				Category:   path,
			})
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "os.remove(") || strings.Contains(trimmed, "os.unlink(") || strings.Contains(trimmed, "shutil.rmtree(") {
			for j := i - 3; j < i; j++ {
				if j >= 0 {
					prev := strings.TrimSpace(lines[j])
					if strings.HasPrefix(prev, "if os.path.exists(") || strings.HasPrefix(prev, "if os.path.isfile(") || strings.HasPrefix(prev, "if os.path.isdir(") {
						return findings
					}
				}
			}
			findings = append(findings, types.Finding{
				Rule:       "unchecked-file-remove",
				Severity:   types.SeverityWarning,
				Message:    "File removal without checking existence — may raise FileNotFoundError",
				Line:       i + 1,
				Suggestion: "Prefer os.path.exists() check or use ignore_errors=True",
				Category:   path,
			})
		}
	}

	return findings
}

func (d *LogicDetector) checkPythonInfiniteLoops(content, path string) []types.Finding {
	return d.checkInfiniteLoops(content, path)
}
