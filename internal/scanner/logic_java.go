package scanner

import (
	"fmt"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

func (d *LogicDetector) detectJava(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if strings.Contains(trimmed, "== ") && strings.Contains(trimmed, ".equals") {
			continue
		}
		if strings.Contains(trimmed, "!= ") && strings.Contains(trimmed, ".equals") {
			continue
		}
		if strings.Contains(trimmed, "if (") || strings.Contains(trimmed, "while (") || strings.Contains(trimmed, "return ") {
			if strings.Contains(trimmed, " == ") || strings.Contains(trimmed, " != ") {
				continue
			}
		}
		stringEq := false
		if strings.Contains(trimmed, ".equals(") {
			continue
		}
		if strings.Contains(trimmed, "\"") && strings.Contains(trimmed, "==") {
			stringEq = true
		}
		if strings.Contains(trimmed, "String") && strings.Contains(trimmed, "==") {
			stringEq = true
		}
		if stringEq {
			findings = append(findings, types.Finding{
				Rule:       "string-equality",
				Severity:   types.SeverityError,
				Message:    "String comparison using == instead of .equals() — compares references, not values",
				Line:       i + 1,
				Suggestion: "Use string1.equals(string2) or Objects.equals() for null-safe comparison",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "catch (") && strings.Contains(trimmed, "Exception e") {
			nl := ""
			if i+1 < len(lines) {
				nl = strings.TrimSpace(lines[i+1])
			}
			if nl == "{}" || nl == "{" && i+2 < len(lines) && strings.TrimSpace(lines[i+2]) == "}" {
				findings = append(findings, types.Finding{
					Rule:       "empty-catch-block",
					Severity:   types.SeverityError,
					Message:    "Empty catch block silently swallows exceptions",
					Line:       i + 1,
					Suggestion: "Log the exception or rethrow it instead of swallowing",
					Category:   path,
				})
			}
		}

		if strings.Contains(trimmed, "switch (") {
			hasDefault := false
			for j := i + 1; j < len(lines) && j < i+50; j++ {
				sl := strings.TrimSpace(lines[j])
				if sl == "default:" || sl == "default :" {
					hasDefault = true
					break
				}
				if sl == "}" {
					break
				}
			}
			if !hasDefault {
				findings = append(findings, types.Finding{
					Rule:       "missing-default-switch",
					Severity:   types.SeverityWarning,
					Message:    "Switch statement without default case — unhandled values silently ignored",
					Line:       i + 1,
					Suggestion: "Add a default case to handle unexpected values",
					Category:   path,
				})
			}
		}

		if strings.Contains(trimmed, "null") && (strings.Contains(trimmed, ".") && strings.Contains(trimmed, "=")) {
			parts := strings.Split(trimmed, "=")
			if len(parts) == 2 {
				lhs := strings.TrimSpace(parts[0])
				rhs := strings.TrimSpace(parts[1])
				if strings.HasSuffix(rhs, ";") {
					rhs = rhs[:len(rhs)-1]
				}
				if strings.TrimSpace(rhs) == "null" && !strings.HasPrefix(lhs, "//") {
					varName := lhs
					if strings.Contains(lhs, " ") {
						parts2 := strings.Fields(lhs)
						varName = parts2[len(parts2)-1]
					}
					if varName != "" {
						assigned := varName
						_ = assigned
					}
				}
			}
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "new File(") || strings.Contains(trimmed, "new FileInputStream(") ||
			strings.Contains(trimmed, "new FileOutputStream(") || strings.Contains(trimmed, "FileReader(") ||
			strings.Contains(trimmed, "FileWriter(") {
			hasTryWithResources := false
			for j := i - 2; j <= i; j++ {
				if j >= 0 && strings.Contains(lines[j], "try (") {
					hasTryWithResources = true
					break
				}
			}
			if !hasTryWithResources {
				hasClose := false
				for j := i + 1; j < len(lines) && j < i+20; j++ {
					if strings.Contains(lines[j], ".close()") {
						hasClose = true
						break
					}
				}
				if !hasClose {
					findings = append(findings, types.Finding{
						Rule:       "resource-leak",
						Severity:   types.SeverityError,
						Message:    "File resource opened without try-with-resources or explicit close()",
						Line:       i + 1,
						Suggestion: "Use try-with-resources: try (Resource r = new Resource(...)) { ... }",
						Category:   path,
					})
				}
			}
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "System.out.println(") || strings.Contains(trimmed, "System.err.println(") {
			findings = append(findings, types.Finding{
				Rule:       "system-out-println",
				Severity:   types.SeverityInfo,
				Message:    "Use logger instead of System.out/err.println for production code",
				Line:       i + 1,
				Suggestion: "Use a logging framework (SLF4J, Log4j, java.util.logging)",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "public class ") || strings.Contains(trimmed, "public interface ") {
			if !strings.HasSuffix(strings.TrimSpace(trimmed), "{") && !strings.Contains(trimmed, "extends ") && !strings.Contains(trimmed, "implements ") {
				fileName := path
				if strings.Contains(fileName, "/") {
					parts := strings.Split(fileName, "/")
					fileName = parts[len(parts)-1]
				}
				className := ""
				idx1 := strings.Index(trimmed, "class ")
				idx2 := strings.Index(trimmed, "interface ")
				if idx1 >= 0 {
					rest := trimmed[idx1+6:]
					parts := strings.Fields(rest)
					if len(parts) > 0 {
						className = parts[0]
					}
				} else if idx2 >= 0 {
					rest := trimmed[idx2+10:]
					parts := strings.Fields(rest)
					if len(parts) > 0 {
						className = parts[0]
					}
				}
				if className != "" && fileName != className+".java" {
					findings = append(findings, types.Finding{
						Rule:       "class-filename-mismatch",
						Severity:   types.SeverityError,
						Message:    fmt.Sprintf("Class '%s' should be in %s.java, not %s", className, className, fileName),
						Line:       i + 1,
						Suggestion: fmt.Sprintf("Rename file to %s.java or rename class to match filename", className),
						Category:   path,
					})
				}
			}
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "float ") || strings.Contains(trimmed, "double ") {
			if strings.Contains(trimmed, " = ") && !strings.Contains(trimmed, ".") && !strings.Contains(trimmed, "f") && !strings.Contains(trimmed, "d") {
				rhs := ""
				eqIdx := strings.Index(trimmed, "=")
				if eqIdx >= 0 {
					rhs = strings.TrimSpace(trimmed[eqIdx+1:])
					if strings.HasSuffix(rhs, ";") {
						rhs = rhs[:len(rhs)-1]
					}
					rhs = strings.TrimSpace(rhs)
				}
				if rhs != "" && !strings.Contains(rhs, ".") && !strings.Contains(rhs, "f") && !strings.Contains(rhs, "d") {
					findings = append(findings, types.Finding{
						Rule:       "integer-division-truncation",
						Severity:   types.SeverityWarning,
						Message:    fmt.Sprintf("Possible integer division truncation assigning to floating-point"),
						Line:       i + 1,
						Suggestion: "Use literal suffix (e.g., 1.0 or 1f) to force floating-point division",
						Category:   path,
					})
				}
			}
		}
	}

	return findings
}

func (d *LogicDetector) checkJavaInfiniteLoops(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "while (true) {" || trimmed == "while(true) {" || strings.HasPrefix(trimmed, "for (;;)") || strings.HasPrefix(trimmed, "for(;;)") {
			hasBreak := false
			hasReturn := false
			for j := i + 1; j < len(lines) && j < i+30; j++ {
				nested := strings.TrimSpace(lines[j])
				if nested == "break;" || strings.HasPrefix(nested, "break;") || nested == "return;" || strings.HasPrefix(nested, "return") {
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
					Message:    "Infinite loop detected — no break or return found within 30 lines",
					Line:       i + 1,
					Suggestion: "Add a break condition or return statement inside the loop body",
					Category:   path,
				})
			}
		}
	}

	return findings
}
