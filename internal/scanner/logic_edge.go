package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)
func (d *LogicDetector) checkInfiniteLoops(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "for {" ) || strings.HasPrefix(trimmed, "for ;;") {
			hasBreak := false
			hasReturn := false
			for j := i + 1; j < len(lines) && j < i+30; j++ {
				nested := strings.TrimSpace(lines[j])
				if strings.HasPrefix(nested, "break") || strings.HasPrefix(nested, "return") {
					hasBreak = true
					hasReturn = true
					break
				}
				if nested == "}" {
					break
				}
			}
			if !hasBreak && !hasReturn {
				findings = append(findings, types.Finding{
					Rule:       "infinite-loop",
					Severity:   types.SeverityError,
					Message:    "Infinite loop detected — no break, return, or condition found within 30 lines",
					Line:       i + 1,
					Suggestion: "Add a break condition or return statement inside the loop",
					Category:   path,
				})
			}
		}
	}

	return findings
}

func (d *LogicDetector) checkEdgeCases(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	hasSliceParam := false
	hasNilCheck := false
	hasMapParam := false
	hasMapNilCheck := false
	hasChanParam := false
	hasChanCloseCheck := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		slicePattern := regexp.MustCompile(`\[\](\w+)`)
		mapPattern := regexp.MustCompile(`map\[`)
		chanPattern := regexp.MustCompile(`chan `)

		if slicePattern.MatchString(trimmed) {
			hasSliceParam = true
		}
		if mapPattern.MatchString(trimmed) {
			hasMapParam = true
		}
		if chanPattern.MatchString(trimmed) {
			hasChanParam = true
		}
		if strings.Contains(trimmed, "nil") && (strings.Contains(trimmed, "==") || strings.Contains(trimmed, "!=")) {
			hasNilCheck = true
			hasMapNilCheck = true
		}
		if strings.Contains(trimmed, "close(") {
			hasChanCloseCheck = true
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if hasSliceParam && !hasNilCheck {
			if strings.Contains(trimmed, "len(") && strings.Contains(trimmed, ") == 0") {
				continue
			}
		}

		if hasMapParam && !hasMapNilCheck {
			if strings.Contains(trimmed, "make(") && strings.Contains(trimmed, "map") {
				continue
			}
		}

		if hasChanParam && !hasChanCloseCheck {
			if strings.Contains(trimmed, "defer close(") || strings.Contains(trimmed, "close(") {
				continue
			}
		}

		if strings.Contains(trimmed, ".Close(") && strings.HasPrefix(trimmed, "resp.") {
			if !strings.Contains(trimmed, "defer") {
				hasDefer := false
				for j := i - 5; j < i; j++ {
					if j >= 0 && strings.Contains(lines[j], "defer") && strings.Contains(lines[j], ".Close") {
						hasDefer = true
						break
					}
				}
				if !hasDefer {
					findings = append(findings, types.Finding{
						Rule:       "missing-defer-close",
						Severity:   types.SeverityWarning,
						Message:    "Resource .Close() called without defer — may leak under error paths",
						Line:       i + 1,
						Suggestion: "Use 'defer resource.Close()' immediately after creating the resource",
						Category:   path,
					})
				}
			}
		}
	}

	linesForVars := content
	varDecl := regexp.MustCompile(`var\s+(\w+)\s+(\w+)`)
	matches := varDecl.FindAllStringSubmatch(linesForVars, -1)
	for _, m := range matches {
		varName := m[1]
		varType := m[2]
		if strings.HasPrefix(varType, "[]") || strings.HasPrefix(varType, "map[") || strings.HasPrefix(varType, "chan ") {
			used := strings.Count(linesForVars, varName)
			if used <= 1 {
				findings = append(findings, types.Finding{
					Rule:       "unused-declaration",
					Severity:   types.SeverityInfo,
					Message:    fmt.Sprintf("Variable '%s' of type '%s' declared but only referenced once", varName, varType),
					Suggestion: "Check if this variable is needed, or if it's a leftover from refactoring",
					Category:   path,
				})
			}
		}
	}

	return findings
}

func (d *LogicDetector) checkMutableDefault(line string, lineNum int, path string) types.Finding {
	return types.Finding{}
}

func (d *LogicDetector) detectCommon(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if strings.Contains(trimmed, "<= 0") || strings.Contains(trimmed, "< 0") {
			findings = append(findings, types.Finding{
				Rule:       "inclusive-zero-check",
				Severity:   types.SeverityInfo,
				Message:    "Bound check includes 0 — may not be intentional",
				Line:       i + 1,
				Suggestion: "Verify that zero should be included in this comparison",
				Category:   path,
			})
		}

		commentCheck := strings.Count(trimmed, "/") >= 4
		codeCheck := strings.Count(trimmed, "//") == 0 && strings.Count(trimmed, "/*") == 0
		if commentCheck && codeCheck {
			if strings.Contains(trimmed, "if ") || strings.Contains(trimmed, "for ") || strings.Contains(trimmed, "return ") {
				continue
			}
		}
	}

	return findings
}
