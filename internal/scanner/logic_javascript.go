package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

func (d *LogicDetector) detectJavaScriptDeep(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if strings.Contains(trimmed, "parseInt(") && !strings.Contains(trimmed, ",") {
			findings = append(findings, types.Finding{
				Rule:       "missing-radix",
				Severity:   types.SeverityWarning,
				Message:    "parseInt() called without radix — default base may be octal or decimal",
				Line:       i + 1,
				Suggestion: "Add radix as second argument: parseInt(str, 10)",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "console.log(") {
			findings = append(findings, types.Finding{
				Rule:       "console-log",
				Severity:   types.SeverityInfo,
				Message:    "console.log() left in code — may leak information to browser console",
				Line:       i + 1,
				Suggestion: "Remove or replace with a proper logging framework",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "delete ") && strings.Contains(trimmed, ".") {
			findings = append(findings, types.Finding{
				Rule:       "delete-operator",
				Severity:   types.SeverityInfo,
				Message:    "Using delete operator on object property — causes performance degradation",
				Line:       i + 1,
				Suggestion: "Use obj[key] = undefined or object spread to omit properties",
				Category:   path,
			})
		}

		if (strings.Contains(trimmed, "for (") || strings.Contains(trimmed, "for(")) && strings.Contains(trimmed, "in ") {
			if !strings.Contains(trimmed, "hasOwnProperty") {
				findings = append(findings, types.Finding{
					Rule:       "for-in-without-hasownproperty",
					Severity:   types.SeverityWarning,
					Message:    "for...in without hasOwnProperty check iterates prototype properties",
					Line:       i + 1,
					Suggestion: "Add hasOwnProperty check or use for...of with Object.keys()",
					Category:   path,
				})
			}
		}

		fnMatch := regexp.MustCompile(`function\s+(\w+)\s*\(`).FindStringSubmatch(trimmed)
		if len(fnMatch) > 1 {
			hasStrict := false
			for j := i + 1; j < len(lines) && j < i+5; j++ {
				if strings.Contains(lines[j], `"use strict"`) || strings.Contains(lines[j], `'use strict'`) {
					hasStrict = true
					break
				}
			}
			if !hasStrict && fnMatch[1][0] >= 'A' && fnMatch[1][0] <= 'Z' {
				if !strings.HasPrefix(trimmed, "class ") {
					findings = append(findings, types.Finding{
						Rule:       "constructor-function-without-strict",
						Severity:   types.SeverityInfo,
						Message:    fmt.Sprintf("Constructor function '%s' should use 'use strict' — missing 'new' will silently create globals", fnMatch[1]),
						Line:       i + 1,
						Suggestion: "Add 'use strict' at the top of the function body",
						Category:   path,
					})
				}
			}
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "callback(") || strings.Contains(trimmed, "cb(") || strings.Contains(trimmed, "next(") {
			hasIf := false
			for j := i - 3; j < i; j++ {
				if j >= 0 && strings.Contains(lines[j], "if ") {
					hasIf = true
					break
				}
			}
			if !hasIf {
				hasErrParam := false
				for _, p := range []string{"err", "error", "e"} {
					if strings.Contains(line, p) {
						hasErrParam = true
					}
				}
				if !hasErrParam {
					findings = append(findings, types.Finding{
						Rule:       "callback-without-error-check",
						Severity:   types.SeverityWarning,
						Message:    fmt.Sprintf("Callback invoked without preceding error check"),
						Line:       i + 1,
						Suggestion: "Check for error before invoking callback",
						Category:   path,
					})
				}
			}
		}
	}

	return findings
}
