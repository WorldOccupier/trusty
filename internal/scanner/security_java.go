package scanner

import (
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

func (s *SecurityScanner) scanJava(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		findings = append(findings, s.checkSQLInjection(trimmed, i+1, path)...)
		findings = append(findings, s.checkHardcodedSecrets(trimmed, i+1, path)...)

		if strings.Contains(trimmed, "Runtime.getRuntime().exec(") || strings.Contains(trimmed, "Runtime.getRuntime().exec(") {
			if !strings.Contains(trimmed, "new String") && !strings.Contains(trimmed, "split(") {
				findings = append(findings, types.Finding{
					Rule:       "command-injection",
					Severity:   types.SeverityError,
					Message:    "Potential command injection — Runtime.exec() with user input",
					Line:       i + 1,
					Suggestion: "Use ProcessBuilder with argument list instead of shell string",
					Category:   path,
				})
			}
		}

		if strings.Contains(trimmed, "ProcessBuilder") && strings.Contains(trimmed, ".start()") {
			if !strings.Contains(trimmed, "redirectErrorStream") {
				findings = append(findings, types.Finding{
					Rule:       "processbuilder-no-error-redirect",
					Severity:   types.SeverityWarning,
					Message:    "Process started without redirectErrorStream — stderr may cause deadlock",
					Line:       i + 1,
					Suggestion: "Add .redirectErrorStream(true) to avoid potential deadlock",
					Category:   path,
				})
			}
		}

		if strings.Contains(trimmed, ".getConnection(") && strings.Contains(trimmed, "+") {
			findings = append(findings, types.Finding{
				Rule:       "sql-injection",
				Severity:   types.SeverityError,
				Message:    "Possible SQL injection — string concatenation in JDBC connection string",
				Line:       i + 1,
				Suggestion: "Use PreparedStatement with parameterized queries",
				Category:   path,
			})
		}

		if (strings.Contains(trimmed, "javax.crypto") || strings.Contains(trimmed, "javax.crypto.spec")) &&
			strings.Contains(trimmed, "DES") && !strings.Contains(trimmed, "AES") && !strings.Contains(trimmed, "AES") {
			findings = append(findings, types.Finding{
				Rule:       "insecure-crypto",
				Severity:   types.SeverityError,
				Message:    "DES/3DES is deprecated and insecure — use AES/GCM/ChaCha20",
				Line:       i + 1,
				Suggestion: "Replace DES/3DES with AES-256 or ChaCha20-Poly1305",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "@RequestMapping") || strings.Contains(trimmed, "@GetMapping") ||
			strings.Contains(trimmed, "@PostMapping") || strings.Contains(trimmed, "@PutMapping") ||
			strings.Contains(trimmed, "@DeleteMapping") {
			if !strings.Contains(content, "@Valid") && !strings.Contains(content, "@Validated") {
				if strings.Contains(trimmed, "@PostMapping") || strings.Contains(trimmed, "@PutMapping") {
					findings = append(findings, types.Finding{
						Rule:       "missing-input-validation",
						Severity:   types.SeverityWarning,
						Message:    "REST endpoint without @Valid annotation — request body not validated",
						Line:       i + 1,
						Suggestion: "Add @Valid to method parameter to enable Bean Validation",
						Category:   path,
					})
				}
			}
		}

		if strings.Contains(trimmed, "new String(") && strings.Contains(trimmed, ".getBytes(") {
			findings = append(findings, types.Finding{
				Rule:       "string-charset-roundtrip",
				Severity:   types.SeverityInfo,
				Message:    "String(bytes) then .getBytes() round-trip may corrupt data — specify charset explicitly",
				Line:       i + 1,
				Suggestion: "Always specify charset: new String(bytes, StandardCharsets.UTF_8)",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "Thread.sleep(") {
			findings = append(findings, types.Finding{
				Rule:       "thread-sleep-in-code",
				Severity:   types.SeverityInfo,
				Message:    "Thread.sleep() used — consider using ScheduledExecutorService for timing",
				Line:       i + 1,
				Suggestion: "Replace Thread.sleep() with ScheduledExecutorService.schedule()",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, ".readObject(") {
			findings = append(findings, types.Finding{
				Rule:       "unsafe-deserialization",
				Severity:   types.SeverityError,
				Message:    "Unsafe Java deserialization — readObject() can lead to RCE",
				Line:       i + 1,
				Suggestion: "Use a whitelist-based deserialization filter or avoid Java serialization",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "new Cookie(") || strings.Contains(trimmed, "new javax.servlet.http.Cookie(") {
			if !strings.Contains(trimmed, "setSecure(true)") && !strings.Contains(trimmed, "setHttpOnly(true)") {
				findings = append(findings, types.Finding{
					Rule:       "insecure-cookie",
					Severity:   types.SeverityWarning,
					Message:    "Cookie created without Secure/HttpOnly flags",
					Line:       i + 1,
					Suggestion: "Add cookie.setSecure(true) and cookie.setHttpOnly(true)",
					Category:   path,
				})
			}
		}
	}

	return findings
}
