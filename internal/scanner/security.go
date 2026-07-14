package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

type SecurityScanner struct{}

func NewSecurityScanner() *SecurityScanner {
	return &SecurityScanner{}
}

func (s *SecurityScanner) Scan(files []types.DiffFile) []types.Finding {
	var findings []types.Finding

	for _, file := range files {
		lang := file.Language
		switch lang {
		case "go":
			findings = append(findings, s.scanGo(file.Content, file.Path)...)
		case "python":
			findings = append(findings, s.scanPython(file.Content, file.Path)...)
		case "typescript", "javascript":
			findings = append(findings, s.scanJavaScript(file.Content, file.Path)...)
		}
		for i := range findings {
			if findings[i].Category == "" {
				findings[i].Category = file.Path
			}
		}
	}

	return findings
}

func (s *SecurityScanner) scanGo(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		findings = append(findings, s.checkSQLInjection(trimmed, i+1, path)...)
		findings = append(findings, s.checkXSS(trimmed, i+1, path)...)
		findings = append(findings, s.checkHardcodedSecrets(trimmed, i+1, path)...)
		findings = append(findings, s.checkCommandInjection(trimmed, i+1, path)...)
		findings = append(findings, s.checkPathTraversal(trimmed, i+1, path)...)
		findings = append(findings, s.checkInsecureCrypto(trimmed, i+1, path)...)

		if strings.Contains(trimmed, "rand.Intn") || strings.Contains(trimmed, "math/rand") {
			if strings.Contains(trimmed, "crypto/rand") || strings.Contains(trimmed, "\"crypto/rand\"") {
				continue
			}
			if !strings.Contains(content, "\"crypto/rand\"") {
				findings = append(findings, types.Finding{
					Rule:       "insecure-random",
					Severity:   types.SeverityWarning,
					Message:    "Using math/rand for security-sensitive randomness — use crypto/rand instead",
					Line:       i + 1,
					Suggestion: "Replace math/rand with crypto/rand for cryptographic contexts",
					Category:   path,
				})
			}
		}
	}

	return findings
}

func (s *SecurityScanner) scanPython(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "\"\"\"") {
			continue
		}

		findings = append(findings, s.checkSQLInjection(trimmed, i+1, path)...)

		if strings.Contains(trimmed, "os.system(") || strings.Contains(trimmed, "subprocess.call(") || strings.Contains(trimmed, "subprocess.Popen(") || strings.Contains(trimmed, "os.popen(") {
			if !strings.Contains(trimmed, "shlex.quote") && !strings.Contains(trimmed, "shlex.escape") {
				findings = append(findings, types.Finding{
					Rule:       "command-injection",
					Severity:   types.SeverityError,
					Message:    "Potential command injection — user input in shell command without escaping",
					Line:       i + 1,
					Suggestion: "Use shlex.quote() to escape arguments or use subprocess.run with argument list",
					Category:   path,
				})
			}
		}

		findings = append(findings, s.checkHardcodedSecrets(trimmed, i+1, path)...)

		if strings.Contains(trimmed, "eval(") || strings.Contains(trimmed, "exec(") {
			if strings.Contains(trimmed, "ast.literal_eval") {
				continue
			}
			findings = append(findings, types.Finding{
				Rule:       "dangerous-eval",
				Severity:   types.SeverityError,
				Message:    "Use of eval()/exec() can lead to code injection",
				Line:       i + 1,
				Suggestion: "Use safer alternatives like ast.literal_eval() for parsing",
				Category:   path,
			})
		}
	}

	return findings
}

func (s *SecurityScanner) scanJavaScript(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		findings = append(findings, s.checkSQLInjection(trimmed, i+1, path)...)
		findings = append(findings, s.checkXSS(trimmed, i+1, path)...)
		findings = append(findings, s.checkHardcodedSecrets(trimmed, i+1, path)...)

		if strings.Contains(trimmed, "innerHTML") || strings.Contains(trimmed, "outerHTML") {
			if strings.Contains(trimmed, "textContent") || strings.Contains(trimmed, "innerText") {
				continue
			}
			findings = append(findings, types.Finding{
				Rule:       "xss-inner-html",
				Severity:   types.SeverityError,
				Message:    "Setting innerHTML with user data can lead to XSS — use textContent instead",
				Line:       i + 1,
				Suggestion: "Use textContent or sanitize input with DOMPurify before setting innerHTML",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "document.write(") {
			findings = append(findings, types.Finding{
				Rule:       "xss-document-write",
				Severity:   types.SeverityError,
				Message:    "document.write() can lead to XSS — use DOM manipulation methods instead",
				Line:       i + 1,
				Suggestion: "Use createElement/appendChild or innerHTML with sanitization",
				Category:   path,
			})
		}
	}

	return findings
}

func (s *SecurityScanner) checkSQLInjection(line string, lineNum int, path string) []types.Finding {
	var findings []types.Finding

	sqlPatterns := []string{
		`(?i)(select|insert|update|delete|create|drop|alter).*\+.*(user|input|param|query|arg)`,
		`(?i)Sprintf\(.*".*select|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER`,
		`\.Query\(.*\+`,
		`\.Exec\(.*\+`,
		`\.Prepare\(.*\+`,
	}

	for _, pattern := range sqlPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(line) && !strings.Contains(line, "?") && !strings.Contains(line, "$1") && !strings.Contains(line, "%s") {
			findings = append(findings, types.Finding{
				Rule:       "sql-injection",
				Severity:   types.SeverityError,
				Message:    "Possible SQL injection — string concatenation in SQL query",
				Line:       lineNum,
				Suggestion: "Use parameterized queries (e.g., $1, ?, :param) instead of string concatenation",
				Category:   path,
			})
			break
		}
	}

	return findings
}

func (s *SecurityScanner) checkXSS(line string, lineNum int, path string) []types.Finding {
	var findings []types.Finding

	if strings.Contains(line, "fmt.Sprintf") && strings.Contains(line, "<") && strings.Contains(line, ">") {
		if !strings.Contains(line, "html.EscapeString") && !strings.Contains(line, "template.HTMLEscape") && !strings.Contains(line, "template.HTML") {
			findings = append(findings, types.Finding{
				Rule:       "xss-html-output",
				Severity:   types.SeverityWarning,
				Message:    "HTML string constructed without escaping — potential XSS vulnerability",
				Line:       lineNum,
				Suggestion: "Use html.EscapeString() or html/template package for HTML output",
				Category:   path,
			})
		}
	}

	return findings
}

func (s *SecurityScanner) checkHardcodedSecrets(line string, lineNum int, path string) []types.Finding {
	var findings []types.Finding

	secretPatterns := []struct {
		pattern *regexp.Regexp
		name    string
	}{
		{regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]`), "API key"},
		{regexp.MustCompile(`(?i)(secret|token|password|passwd)\s*[:=]\s*['\"][A-Za-z0-9_\-!@#$%^&*()]{8,}['\"]`), "secret/token/password"},
		{regexp.MustCompile(`(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----`), "private key"},
		{regexp.MustCompile(`(?i)ghp_[A-Za-z0-9]{36}`), "GitHub token"},
		{regexp.MustCompile(`(?i)sk-[A-Za-z0-9]{32,}`), "OpenAI API key"},
		{regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), "AWS access key"},
	}

	for _, sp := range secretPatterns {
		if sp.pattern.MatchString(line) {
			findings = append(findings, types.Finding{
				Rule:       "hardcoded-secret",
				Severity:   types.SeverityError,
				Message:    fmt.Sprintf("Hardcoded %s found in source code", sp.name),
				Line:       lineNum,
				Suggestion: "Use environment variables or a secret manager (e.g., Vault, AWS Secrets Manager)",
				Category:   path,
			})
			break
		}
	}

	return findings
}

func (s *SecurityScanner) checkCommandInjection(line string, lineNum int, path string) []types.Finding {
	var findings []types.Finding

	execPatterns := []string{
		`os/exec.*Command.*\+`,
		`exec\.Command\(.*\+`,
		`exec\.CommandContext\(.*\+`,
		`syscall\.Exec\(.*\+`,
	}

	for _, pattern := range execPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(line) {
			findings = append(findings, types.Finding{
				Rule:       "command-injection",
				Severity:   types.SeverityError,
				Message:    "Possible command injection — string concatenation in exec.Command",
				Line:       lineNum,
				Suggestion: "Use argument list form: exec.Command(name, arg1, arg2) instead of shell syntax",
				Category:   path,
			})
			break
		}
	}

	return findings
}

func (s *SecurityScanner) checkPathTraversal(line string, lineNum int, path string) []types.Finding {
	var findings []types.Finding

	traversalPatterns := []string{
		`os\.Open\(.*\+`,
		`os\.ReadFile\(.*\+`,
		`os\.WriteFile\(.*\+`,
		`ioutil\.ReadFile\(.*\+`,
		`ioutil\.WriteFile\(.*\+`,
		`filepath\.Join\(.*\.\.`,
		`http\.Dir\(.*\+`,
		`http\.FS\(.*\+`,
	}

	for _, pattern := range traversalPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(line) {
			clean := true
			if strings.Contains(line, "filepath.Clean") || strings.Contains(line, "filepath.Base") {
				clean = false
			}
			if clean {
				findings = append(findings, types.Finding{
					Rule:       "path-traversal",
					Severity:   types.SeverityError,
					Message:    "Possible path traversal — user input in file path without validation",
					Line:       lineNum,
					Suggestion: "Use filepath.Clean() and filepath.Base() to sanitize file paths",
					Category:   path,
				})
				break
			}
		}
	}

	return findings
}

func (s *SecurityScanner) checkInsecureCrypto(line string, lineNum int, path string) []types.Finding {
	var findings []types.Finding

	insecure := map[string]string{
		"md5":    "MD5 is not cryptographically secure — use SHA-256 or SHA-3",
		"sha1":   "SHA-1 is not cryptographically secure — use SHA-256 or SHA-3",
		"des.NewCipher": "DES is deprecated and insecure — use AES",
		"rc4":    "RC4 is broken and insecure — use AES-GCM or ChaCha20",
	}

	for algo, msg := range insecure {
		if strings.Contains(line, algo) {
			if strings.Contains(line, "//") || strings.Contains(line, "insecure") || strings.Contains(line, "deprecated") || strings.Contains(line, "_ =") {
				continue
			}
			if algo == "sha1" && strings.Contains(line, "sha256") {
				continue
			}
			findings = append(findings, types.Finding{
				Rule:       "insecure-crypto",
				Severity:   types.SeverityError,
				Message:    msg,
				Line:       lineNum,
				Suggestion: fmt.Sprintf("Replace %s usage with a secure alternative", algo),
				Category:   path,
			})
			break
		}
	}

	return findings
}
