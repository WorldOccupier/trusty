package fixer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

type Fixer struct {
	DryRun      bool
	Interactive bool
	Fixed       int
	Skipped     int
	Errors      int
}

func New() *Fixer {
	return &Fixer{}
}

type FixResult struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
	Applied bool   `json:"applied"`
}

func (f *Fixer) ApplyFindings(findings []types.Finding, sourceDir string) ([]FixResult, error) {
	var results []FixResult
	fileFindings := groupByFile(findings)

	for filePath, ff := range fileFindings {
		fullPath := filepath.Join(sourceDir, filePath)
		content, err := os.ReadFile(filepath.Clean(fullPath))
		if err != nil {
			for range ff {
				results = append(results, FixResult{
					File:    filePath,
					Message: "Could not read file",
					Applied: false,
				})
				f.Errors++
			}
			continue
		}

		lines := strings.Split(string(content), "\n")
		modified := make([]string, len(lines))
		copy(modified, lines)

		for _, finding := range ff {
			fix := generateFix(finding)
			if fix == "" {
				results = append(results, FixResult{
					File:    filePath,
					Line:    finding.Line,
					Rule:    finding.Rule,
					Message: finding.Message,
					Fix:     "No auto-fix available",
					Applied: false,
				})
				f.Skipped++
				continue
			}

			result := FixResult{
				File:    filePath,
				Line:    finding.Line,
				Rule:    finding.Rule,
				Message: finding.Message,
				Fix:     fix,
			}

			if f.Interactive {
				fmt.Printf("\n%s:%d\n", filePath, finding.Line)
				fmt.Printf("  Issue: %s\n", finding.Message)
				fmt.Printf("  Suggestion: %s\n", fix)
				fmt.Printf("  Apply? [y/N] ")
				var response string
				fmt.Scanln(&response)
				response = strings.TrimSpace(strings.ToLower(response))
				if response != "y" && response != "yes" {
					result.Applied = false
					results = append(results, result)
					f.Skipped++
					continue
				}
			}

			if f.DryRun {
				result.Applied = true
				results = append(results, result)
				f.Fixed++
				continue
			}

			newContent := applyFix(modified, finding, fix)
			if newContent != "" {
				modified = strings.Split(newContent, "\n")
				result.Applied = true
				f.Fixed++
			} else {
				result.Applied = false
				f.Errors++
			}
			results = append(results, result)
		}

		if !f.DryRun && !f.Interactive {
			newContent := strings.Join(modified, "\n")
			if err := os.WriteFile(filepath.Clean(fullPath), []byte(newContent), 0644); err != nil {
				return results, fmt.Errorf("writing %s: %w", fullPath, err)
			}
		}
	}

	return results, nil
}

func (f *Fixer) ApplyResultFile(resultPath string, sourceDir string) error {
	data, err := os.ReadFile(filepath.Clean(resultPath))
	if err != nil {
		return fmt.Errorf("reading result file: %w", err)
	}

	var scanResult types.ScanResult
	if err := json.Unmarshal(data, &scanResult); err != nil {
		return fmt.Errorf("parsing result: %w", err)
	}

	var allFindings []types.Finding
	for _, fr := range scanResult.Files {
		allFindings = append(allFindings, fr.Findings...)
	}

	if len(allFindings) == 0 {
		fmt.Println("No findings to fix.")
		return nil
	}

	results, err := f.ApplyFindings(allFindings, sourceDir)
	if err != nil {
		return err
	}

	output, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(output))

	fmt.Fprintf(os.Stderr, "\nFixed: %d, Skipped: %d, Errors: %d\n", f.Fixed, f.Skipped, f.Errors)
	return nil
}

func groupByFile(findings []types.Finding) map[string][]types.Finding {
	grouped := make(map[string][]types.Finding)
	for _, f := range findings {
		file := f.Category
		if file == "" {
			file = "unknown"
		}
		grouped[file] = append(grouped[file], f)
	}
	return grouped
}

func generateFix(finding types.Finding) string {
	if finding.Suggestion != "" {
		return finding.Suggestion
	}

	switch finding.Rule {
	case "nil-dereference":
		return "Add nil check before access"
	case "unchecked-error":
		return "Check and handle the error return value"
	case "missing-deferred-close":
		return "Add defer resource.Close()"
	case "missing-defer-close":
		return "Add defer resource.Close()"
	case "typed-nil-interface":
		return "Return explicit typed nil instead of bare nil"
	case "hardcoded-index":
		return "Add length check or use range loop"
	case "sql-injection":
		return "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = ?\", userID)"
	case "command-injection":
		return "Sanitize input: use allowlist validation on user input before shell execution"
	case "xss-inner-html":
		return "Use textContent instead of innerHTML: element.textContent = sanitizedInput"
	case "xss-document-write":
		return "Avoid document.write(); use DOM manipulation methods"
	case "hardcoded-secret":
		return "Move secret to environment variable: os.Getenv(\"SECRET_NAME\")"
	case "insecure-crypto":
		return "Replace with secure algorithm: crypto/sha256 or bcrypt"
	case "insecure-random":
		return "Use crypto/rand instead of math/rand"
	case "dangerous-eval":
		return "Replace eval() with JSON.parse() or Function constructor"
	case "unused-import":
		return "Remove unused import"
	case "wildcard-import":
		return "Replace wildcard import with explicit imports"
	case "any-type":
		return "Replace 'any' with specific type or 'unknown'"
	case "redundant-equality":
		return "Remove '== True' — use the expression directly as condition"
	case "bare-except":
		return "Replace bare 'except:' with specific exception type"
	case "range-len-pattern":
		return "Replace 'for i in range(len(x))' with 'for i, item in enumerate(x)'"
	case "none-comparison":
		return "Replace '== None' with 'is None'"
	case "assert-used":
		return "Replace 'assert' with proper if/raise for production code"
	case "is-comparison-literal":
		return "Replace 'is True'/'is False' with direct boolean evaluation"
	case "bare-exception-catch":
		return "Add 'as e' to except clause to capture exception details"
	case "ternary-return-boolean":
		return "Simplify 'return True if cond else False' to 'return cond'"
	case "infinite-loop":
		return "Add break condition or return statement inside the loop body"
	case "mutable-default-arg":
		return "Use None as default and create new instance inside function body"
	case "unchecked-file-remove":
		return "Add os.path.exists() check or use ignore_errors=True"
	case "loose-equality":
		return "Replace == with === (or != with !==) for strict comparison"
	case "missing-radix":
		return "Add radix as second argument: parseInt(str, 10)"
	case "console-log":
		return "Remove console.log() or replace with proper logging framework"
	case "delete-operator":
		return "Use obj[key] = undefined or object spread instead of delete"
	case "for-in-without-hasownproperty":
		return "Add hasOwnProperty check or use for...of with Object.keys()"
	case "constructor-function-without-strict":
		return "Add 'use strict' at the top of the function body"
	case "callback-without-error-check":
		return "Check for error before invoking callback"
	case "string-equality":
		return "Use .equals() instead of == for string comparison"
	case "empty-catch-block":
		return "Log the exception or rethrow it instead of swallowing"
	case "missing-default-switch":
		return "Add a default case to handle unexpected values"
	case "resource-leak":
		return "Use try-with-resources: try (Resource r = new Resource(...)) { ... }"
	case "system-out-println":
		return "Use a logging framework (SLF4J, Log4j, java.util.logging)"
	case "class-filename-mismatch":
		return "Rename file to match class name or rename class to match filename"
	case "integer-division-truncation":
		return "Use literal suffix (e.g., 1.0 or 1f) to force floating-point division"
	case "processbuilder-no-error-redirect":
		return "Add .redirectErrorStream(true) to avoid potential deadlock"
	case "missing-input-validation":
		return "Add @Valid annotation to enable Bean Validation"
	case "string-charset-roundtrip":
		return "Always specify charset: new String(bytes, StandardCharsets.UTF_8)"
	case "thread-sleep-in-code":
		return "Replace Thread.sleep() with ScheduledExecutorService.schedule()"
	case "unsafe-deserialization":
		return "Use a whitelist-based deserialization filter or avoid Java serialization"
	case "insecure-cookie":
		return "Add cookie.setSecure(true) and cookie.setHttpOnly(true)"
	case "unwrap-usage":
		return "Replace .unwrap() with match, if let, or ? operator for proper error handling"
	case "panic-in-code":
		return "Replace panic!() with a proper error type and ? propagation"
	case "unsafe-block":
		return "Minimize unsafe blocks and add // SAFETY: comments explaining invariants"
	case "transmute-usage":
		return "Replace mem::transmute() with safe alternatives like bytemuck or From/Into"
	case "string-ref-pattern":
		return "Change &String parameters to &str for broader compatibility"
	case "raw-pointer-cast":
		return "Add // SAFETY: comment explaining why this pointer operation is safe"
	case "unused-variable":
		return "Prefix with _ or remove if unused"
	case "format-string-injection":
		return "Ensure format string is a constant literal, not user-controlled input"
	case "unchecked-write":
		return "Use .unwrap(), ? operator, or match on the Result for write operations"
	case "unsafe-pointer-operation":
		return "Add // SAFETY: comment explaining why this pointer operation is safe"
	case "off-by-one":
		return "Use < instead of <= to avoid iterating one past the intended bound"
	case "inverted-conditional":
		return "Verify the comparison direction is correct"
	case "self-assignment":
		return "Fix self-assignment — assign to a different variable"
	case "missing-default":
		return "Add a default case to handle unexpected values"
	case "inclusive-zero-check":
		return "Verify that zero should be included in this comparison"
	case "unused-declaration":
		return "Check if this variable is needed, or remove if leftover from refactoring"
	case "hallucinated-import":
		return "Verify the package/crate/module exists and is spelled correctly"
	case "dangerous-function":
		return "Replace eval()/exec() with safer alternatives like ast.literal_eval()"
	case "dom-xss":
		return "Sanitize input or use safe APIs like textContent instead of innerHTML"
	case "insecure-comparison":
		return "Replace == with === for security-critical comparisons"
	case "request-no-timeout":
		return "Add timeout parameter: requests.get(url, timeout=10)"
	case "unsafe-pickle":
		return "Use safer serialization format like JSON instead of pickle"
	case "path-traversal":
		return "Use filepath.Clean() and filepath.Base() to sanitize file paths"
	case "weak-jwt-secret":
		return "Use a properly generated random secret of at least 256 bits"
	case "nosql-injection":
		return "Use parameterized queries or sanitize user input before building BSON"
	case "open-redirect":
		return "Validate and sanitize redirect URL against a whitelist"
	case "var-usage":
		return "Replace 'var' with 'const' or 'let'"
	case "unchecked-error-ast":
		return "Check and handle the error return value"
	default:
		return ""
	}
}

func applyFix(lines []string, finding types.Finding, fix string) string {
	idx := finding.Line - 1
	if idx < 0 || idx >= len(lines) {
		return ""
	}

	line := lines[idx]
	trimmed := strings.TrimSpace(line)

	switch finding.Rule {
	case "missing-deferred-close", "missing-defer-close":
		if strings.Contains(fix, "defer") {
			indent := leadingWhitespace(line)
			newLine := indent + extractDefer(fix)
			newLines := make([]string, 0, len(lines)+1)
			newLines = append(newLines, lines[:idx]...)
			newLines = append(newLines, newLine)
			newLines = append(newLines, lines[idx:]...)
			return strings.Join(newLines, "\n")
		}

	case "none-comparison":
		newLine := strings.ReplaceAll(trimmed, "== None", "is None")
		newLine = strings.ReplaceAll(newLine, "!= None", "is not None")
		if newLine != trimmed {
			indent := leadingWhitespace(line)
			lines[idx] = indent + newLine
			return strings.Join(lines, "\n")
		}

	case "var-usage":
		newLine := strings.Replace(trimmed, "var ", "const ", 1)
		if newLine != trimmed {
			indent := leadingWhitespace(line)
			lines[idx] = indent + newLine
			return strings.Join(lines, "\n")
		}

	case "missing-radix":
		if strings.Contains(trimmed, "parseInt(") && !strings.Contains(trimmed, ",") {
			newLine := strings.Replace(trimmed, "parseInt(", "parseInt(", 1)
			if strings.HasSuffix(newLine, ")") {
				newLine = newLine[:len(newLine)-1] + ", 10)"
			} else if strings.HasSuffix(newLine, ");") {
				newLine = newLine[:len(newLine)-2] + ", 10);"
			}
			if newLine != trimmed {
				indent := leadingWhitespace(line)
				lines[idx] = indent + newLine
				return strings.Join(lines, "\n")
			}
		}

	case "console-log":
		if strings.Contains(trimmed, "console.log(") {
			newLine := "// " + trimmed
			indent := leadingWhitespace(line)
			lines[idx] = indent + newLine
			return strings.Join(lines, "\n")
		}

	case "system-out-println":
		if strings.Contains(trimmed, "System.out.println(") || strings.Contains(trimmed, "System.err.println(") {
			newLine := "// TODO: replace with logger: " + trimmed
			indent := leadingWhitespace(line)
			lines[idx] = indent + newLine
			return strings.Join(lines, "\n")
		}

	case "redundant-equality":
		if strings.Contains(trimmed, "== True") {
			newLine := strings.ReplaceAll(trimmed, " == True", "")
			if newLine != trimmed {
				indent := leadingWhitespace(line)
				lines[idx] = indent + newLine
				return strings.Join(lines, "\n")
			}
		}

	case "bare-except":
		if trimmed == "except:" || strings.HasPrefix(trimmed, "except:") {
			indent := leadingWhitespace(line)
			lines[idx] = indent + "except Exception:"
			return strings.Join(lines, "\n")
		}

	case "bare-exception-catch":
		if strings.Contains(trimmed, "except Exception:") && !strings.Contains(trimmed, "as ") {
			newLine := strings.Replace(trimmed, "except Exception:", "except Exception as e:", 1)
			if newLine != trimmed {
				indent := leadingWhitespace(line)
				lines[idx] = indent + newLine
				return strings.Join(lines, "\n")
			}
		}
	}

	return ""
}

func leadingWhitespace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return s[:i]
}

func extractDefer(suggestion string) string {
	if idx := strings.Index(suggestion, "defer "); idx >= 0 {
		end := strings.Index(suggestion[idx:], "\n")
		if end < 0 {
			end = len(suggestion[idx:])
		}
		return strings.TrimSpace(suggestion[idx : idx+end])
	}
	return ""
}
