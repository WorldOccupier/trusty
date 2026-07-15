package scanner

import (
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

func (s *SecurityScanner) scanRust(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		findings = append(findings, s.checkHardcodedSecrets(trimmed, i+1, path)...)

		if strings.Contains(trimmed, "std::process::Command::new(") || strings.Contains(trimmed, "Command::new(") {
			if strings.Contains(trimmed, ".arg(") || strings.Contains(trimmed, ".args(") {
				continue
			}
			findings = append(findings, types.Finding{
				Rule:       "command-injection",
				Severity:   types.SeverityError,
				Message:    "Potential command injection — Command::new() with shell-like string concatenation",
				Line:       i + 1,
				Suggestion: "Use .arg() with separate arguments instead of shell strings",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "format!(") || strings.Contains(trimmed, "write!(") || strings.Contains(trimmed, "writeln!(") {
			if strings.Contains(trimmed, "unsafe") {
				continue
			}
			if strings.Contains(trimmed, "{}") && strings.Count(trimmed, "{}") > 0 {
				hasUserInput := false
				userPatterns := []string{"input", "user", "data", "param", "query", "arg", "name", "path"}
				for _, p := range userPatterns {
					if strings.Contains(strings.ToLower(trimmed), p) {
						hasUserInput = true
						break
					}
				}
				if hasUserInput {
					findings = append(findings, types.Finding{
						Rule:       "format-string-injection",
						Severity:   types.SeverityWarning,
						Message:    "User-controlled data in format string — potential injection if format args are user-supplied",
						Line:       i + 1,
						Suggestion: "Ensure format string is a constant literal, not user-controlled input",
						Category:   path,
					})
				}
			}
		}

		if strings.Contains(trimmed, ".write(") || strings.Contains(trimmed, ".write_all(") || strings.Contains(trimmed, ".write_fmt(") {
			if strings.Contains(trimmed, ".unwrap()") {
				continue
			}
			findings = append(findings, types.Finding{
				Rule:       "unchecked-write",
				Severity:   types.SeverityWarning,
				Message:    "Write operation result not handled — I/O errors will be silently ignored",
				Line:       i + 1,
				Suggestion: "Use .unwrap(), ? operator, or match on the Result",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "std::fs::remove") || strings.Contains(trimmed, "std::fs::remove_dir") {
			if !strings.Contains(trimmed, ".unwrap()") && !strings.Contains(trimmed, "?") {
				findings = append(findings, types.Finding{
					Rule:       "unchecked-file-remove",
					Severity:   types.SeverityWarning,
					Message:    "File/directory removal without handling the Result — error will be ignored",
					Line:       i + 1,
					Suggestion: "Handle the Result with ? or match, or use .unwrap() if you're sure",
					Category:   path,
				})
			}
		}

		if strings.Contains(trimmed, "std::ptr") || strings.Contains(trimmed, "core::ptr") {
			if strings.Contains(trimmed, "null_mut") || strings.Contains(trimmed, "null()") ||
				strings.Contains(trimmed, "read(") || strings.Contains(trimmed, "write(") ||
				strings.Contains(trimmed, "replace(") || strings.Contains(trimmed, "swap(") {
				if !strings.Contains(trimmed, "// SAFETY:") {
					findings = append(findings, types.Finding{
						Rule:       "unsafe-pointer-operation",
						Severity:   types.SeverityError,
						Message:    "Unsafe pointer operation without SAFETY justification",
						Line:       i + 1,
						Suggestion: "Add // SAFETY: comment explaining why this operation is safe",
						Category:   path,
					})
				}
			}
		}
	}

	return findings
}
