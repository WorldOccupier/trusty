package scanner

import (
	"fmt"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

func (d *LogicDetector) detectRust(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if strings.Contains(trimmed, ".unwrap()") {
			findings = append(findings, types.Finding{
				Rule:       "unwrap-usage",
				Severity:   types.SeverityWarning,
				Message:    "Using .unwrap() will panic on Err/None — use pattern matching or ? operator instead",
				Line:       i + 1,
				Suggestion: "Replace with match, if let, or ? operator for proper error handling",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "panic!(") || strings.Contains(trimmed, "panic!(\"") {
			findings = append(findings, types.Finding{
				Rule:       "panic-in-code",
				Severity:   types.SeverityWarning,
				Message:    "panic!() used in production code — consider returning Result instead",
				Line:       i + 1,
				Suggestion: "Replace panic!() with a proper error type and ? propagation",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "unsafe {") || strings.Contains(trimmed, "unsafe{") {
			findings = append(findings, types.Finding{
				Rule:       "unsafe-block",
				Severity:   types.SeverityWarning,
				Message:    "Unsafe block bypasses Rust's memory safety guarantees",
				Line:       i + 1,
				Suggestion: "Minimize unsafe blocks and add safety comments (// SAFETY:) explaining invariants",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "loop {") || strings.Contains(trimmed, "loop{") {
			hasControlFlow := false
			for j := i + 1; j < len(lines) && j < i+30; j++ {
				nl := strings.TrimSpace(lines[j])
				if nl == "break" || strings.HasPrefix(nl, "break ") || strings.HasPrefix(nl, "return") {
					hasControlFlow = true
					break
				}
				if nl == "}" && strings.Count(nl, "}") == len(nl) {
					break
				}
				if strings.Count(nl, "{") < strings.Count(nl, "}") {
					break
				}
			}
			if !hasControlFlow {
				findings = append(findings, types.Finding{
					Rule:       "infinite-loop",
					Severity:   types.SeverityError,
					Message:    "Infinite loop without break or return within 30 lines",
					Line:       i + 1,
					Suggestion: "Add a break condition or return statement inside the loop",
					Category:   path,
				})
			}
		}

		if strings.Contains(trimmed, "transmute<") || strings.Contains(trimmed, "transmute::") {
			findings = append(findings, types.Finding{
				Rule:       "transmute-usage",
				Severity:   types.SeverityError,
				Message:    "mem::transmute() is extremely unsafe — reinterpret s arbitrary bytes as another type",
				Line:       i + 1,
				Suggestion: "Use safe alternatives like bytemuck, transmute-rs, or From/Into trait implementations",
				Category:   path,
			})
		}

		fnMatch := strings.HasPrefix(trimmed, "fn ") && strings.Contains(trimmed, "(")
		if fnMatch && strings.Contains(trimmed, "&String") {
			findings = append(findings, types.Finding{
				Rule:       "string-ref-pattern",
				Severity:   types.SeverityInfo,
				Message:    "Using &String instead of &str limits API flexibility — prefer &str",
				Line:       i + 1,
				Suggestion: "Change &String parameters to &str for broader compatibility",
				Category:   path,
			})
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "as *const ") || strings.Contains(trimmed, "as *mut ") {
			if !strings.Contains(trimmed, "// SAFETY:") && !strings.Contains(trimmed, "// SAFETY") {
				findings = append(findings, types.Finding{
					Rule:       "raw-pointer-cast",
					Severity:   types.SeverityInfo,
					Message:    "Raw pointer cast without SAFETY comment — ensure invariants are documented",
					Line:       i + 1,
					Suggestion: "Add // SAFETY: comment explaining why this pointer operation is safe",
					Category:   path,
				})
			}
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "let ") && strings.Contains(trimmed, "= ") {
			nameEnd := strings.Index(trimmed[4:], " ")
			varName := ""
			if nameEnd > 0 {
				varName = trimmed[4 : 4+nameEnd]
			}
			if varName != "" && varName != "mut" && varName != "ref" {
				usageCount := strings.Count(content, varName)
				if usageCount <= 1 && !strings.Contains(trimmed, "_") {
					findings = append(findings, types.Finding{
						Rule:       "unused-variable",
						Severity:   types.SeverityInfo,
						Message:    fmt.Sprintf("Variable '%s' is declared but only used once (the declaration)", varName),
						Line:       i + 1,
						Suggestion: fmt.Sprintf("Prefix with _: _%s, or remove if unused", varName),
						Category:   path,
					})
				}
			}
		}
	}

	return findings
}
