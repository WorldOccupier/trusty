package scanner

import (
	"fmt"
	"math"
	"strings"
	"unicode"
)

type Fingerprinter struct{}

type FingerprintResult struct {
	Score       int                    `json:"score"`
	Signals     []FingerprintSignal    `json:"signals"`
	Verdict     string                 `json:"verdict"`
}

type FingerprintSignal struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail,omitempty"`
}

func NewFingerprinter() *Fingerprinter {
	return &Fingerprinter{}
}

func (f *Fingerprinter) Analyze(content, path string) FingerprintResult {
	lang := detectFingerprintLanguage(path)
	signals := f.collectSignals(content, lang)

	totalScore := 0.0
	totalWeight := 0.0
	for _, s := range signals {
		totalScore += s.Value * s.Weight
		totalWeight += s.Weight
	}

	var score int
	if totalWeight > 0 {
		score = int(math.Round(totalScore / totalWeight))
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	verdict := "likely-human"
	if score >= 70 {
		verdict = "likely-ai"
	} else if score >= 40 {
		verdict = "uncertain"
	}

	return FingerprintResult{
		Score:   score,
		Signals: signals,
		Verdict: verdict,
	}
}

func detectFingerprintLanguage(path string) string {
	if strings.HasSuffix(path, ".go") {
		return "go"
	}
	if strings.HasSuffix(path, ".py") {
		return "python"
	}
	if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".jsx") || strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".tsx") {
		return "javascript"
	}
	return "unknown"
}

func (f *Fingerprinter) collectSignals(content, lang string) []FingerprintSignal {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return nil
	}

	var signals []FingerprintSignal

	signals = append(signals, f.commentDensity(lines, lang))
	signals = append(signals, f.lineLengthUniformity(lines))
	signals = append(signals, f.docCoverage(lines, lang))
	signals = append(signals, f.functionLengthConsistency(content, lang))
	signals = append(signals, f.namingConventionConsistency(lines, lang))
	signals = append(signals, f.repeatedPatterns(lines))
	signals = append(signals, f.importGrouping(lines, lang))
	signals = append(signals, f.errorHandlingVerbosity(lines, lang))

	return signals
}

func (f *Fingerprinter) commentDensity(lines []string, lang string) FingerprintSignal {
	commentLines := 0
	codeLines := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if isComment(trimmed, lang) {
			commentLines++
		} else {
			codeLines++
		}
	}

	total := commentLines + codeLines
	if total == 0 {
		return FingerprintSignal{Name: "comment-density", Value: 0, Weight: 0.15}
	}

	ratio := float64(commentLines) / float64(total)
	score := ratio * 100

	detail := ""
	if ratio > 0.4 {
		detail = "Very high comment density (>40%) — common in AI-generated code"
	} else if ratio > 0.25 {
		detail = "High comment density (>25%) — above average"
	}

	return FingerprintSignal{
		Name:   "comment-density",
		Value:  score,
		Weight: 0.15,
		Detail: detail,
	}
}

func (f *Fingerprinter) lineLengthUniformity(lines []string) FingerprintSignal {
	var lengths []int
	for _, line := range lines {
		if len(line) > 5 {
			lengths = append(lengths, len(line))
		}
	}
	if len(lengths) < 10 {
		return FingerprintSignal{Name: "line-uniformity", Value: 0, Weight: 0.10}
	}

	mean := 0.0
	for _, l := range lengths {
		mean += float64(l)
	}
	mean /= float64(len(lengths))

	variance := 0.0
	for _, l := range lengths {
		d := float64(l) - mean
		variance += d * d
	}
	variance /= float64(len(lengths))
	stddev := math.Sqrt(variance)

	cv := stddev / mean
	aiScore := 0.0
	if cv < 0.3 {
		aiScore = 80.0
	} else if cv < 0.5 {
		aiScore = 40.0
	} else {
		aiScore = 10.0
	}

	detail := ""
	if cv < 0.3 {
		detail = "Very uniform line lengths (CV=" + formatFloat(cv) + ") — typical of AI output"
	}

	return FingerprintSignal{
		Name:   "line-uniformity",
		Value:  aiScore,
		Weight: 0.10,
		Detail: detail,
	}
}

func (f *Fingerprinter) docCoverage(lines []string, lang string) FingerprintSignal {
	funcCount := 0
	docCount := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isFunctionDecl(trimmed, lang) {
			funcCount++
			if i > 0 {
				prev := strings.TrimSpace(lines[i-1])
				if strings.HasPrefix(prev, "// ") || strings.HasPrefix(prev, "/*") || strings.HasPrefix(prev, "/**") || strings.HasPrefix(prev, "# ") || strings.HasPrefix(prev, "\"\"\"") {
					docCount++
				}
			}
		}
	}

	if funcCount == 0 {
		return FingerprintSignal{Name: "doc-coverage", Value: 0, Weight: 0.12}
	}

	ratio := float64(docCount) / float64(funcCount)
	score := ratio * 100

	detail := ""
	if ratio > 0.9 {
		detail = "Very high doc coverage (>90%) — AI tends to document everything"
	}

	return FingerprintSignal{
		Name:   "doc-coverage",
		Value:  score,
		Weight: 0.12,
		Detail: detail,
	}
}

func (f *Fingerprinter) functionLengthConsistency(content, lang string) FingerprintSignal {
	lines := strings.Split(content, "\n")
	var funcLengths []int
	inFunc := false
	braceCount := 0
	startLine := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inFunc && isFunctionDecl(trimmed, lang) {
			inFunc = true
			braceCount = 0
			startLine = i
		}
		if inFunc {
			braceCount += strings.Count(trimmed, "{")
			braceCount -= strings.Count(trimmed, "}")
			if braceCount <= 0 && strings.Contains(trimmed, "}") {
				funcLengths = append(funcLengths, i-startLine+1)
				inFunc = false
			}
		}
	}

	if len(funcLengths) < 3 {
		return FingerprintSignal{Name: "func-length", Value: 0, Weight: 0.10}
	}

	mean := 0.0
	for _, l := range funcLengths {
		mean += float64(l)
	}
	mean /= float64(len(funcLengths))

	variance := 0.0
	for _, l := range funcLengths {
		d := float64(l) - mean
		variance += d * d
	}
	variance /= float64(len(funcLengths))
	stddev := math.Sqrt(variance)

	cv := stddev / mean
	aiScore := 0.0
	if cv < 0.4 {
		aiScore = 70.0
	} else if cv < 0.7 {
		aiScore = 30.0
	} else {
		aiScore = 5.0
	}

	return FingerprintSignal{
		Name:   "func-length",
		Value:  aiScore,
		Weight: 0.10,
	}
}

func (f *Fingerprinter) namingConventionConsistency(lines []string, lang string) FingerprintSignal {
	var names []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "func ") || strings.Contains(trimmed, "def ") {
			parts := strings.Fields(trimmed)
			for _, p := range parts {
				if strings.Contains(p, "(") {
					name := strings.Split(p, "(")[0]
					if name != "" && name != "func" && name != "def" {
						names = append(names, name)
					}
					break
				}
			}
		}
	}

	if len(names) < 3 {
		return FingerprintSignal{Name: "naming-consistency", Value: 0, Weight: 0.10}
	}

	camelCase := 0
	snakeCase := 0
	hasUnderscore := 0

	for _, name := range names {
		if strings.Contains(name, "_") {
			hasUnderscore++
			if isSnakeCase(name) {
				snakeCase++
			}
		}
		if isCamelCase(name) {
			camelCase++
		}
	}

	total := float64(len(names))
	camelRatio := float64(camelCase) / total
	snakeRatio := float64(snakeCase) / total

	dominantRatio := math.Max(camelRatio, snakeRatio)
	if dominantRatio == 0 {
		return FingerprintSignal{Name: "naming-consistency", Value: 0, Weight: 0.10}
	}

	score := dominantRatio * 100

	detail := ""
	if dominantRatio > 0.9 {
		detail = "Very consistent naming (>90%) — AI tends to use uniform conventions"
	}

	return FingerprintSignal{
		Name:   "naming-consistency",
		Value:  score,
		Weight: 0.10,
		Detail: detail,
	}
}

func (f *Fingerprinter) repeatedPatterns(lines []string) FingerprintSignal {
	if len(lines) < 20 {
		return FingerprintSignal{Name: "repeated-patterns", Value: 0, Weight: 0.08}
	}

	seen := make(map[string]int)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 20 {
			key := trimmed[:20]
			seen[key]++
		}
	}

	repeated := 0
	for _, count := range seen {
		if count > 2 {
			repeated++
		}
	}

	score := float64(repeated) / float64(len(seen)) * 100
	if score > 100 {
		score = 100
	}

	return FingerprintSignal{
		Name:   "repeated-patterns",
		Value:  score,
		Weight: 0.08,
	}
}

func (f *Fingerprinter) importGrouping(lines []string, lang string) FingerprintSignal {
	importBlock := false
	stdImports := 0
	thirdPartyImports := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isImportStart(trimmed, lang) {
			importBlock = true
			continue
		}
		if importBlock && isImportEnd(trimmed, lang) {
			importBlock = false
			continue
		}
		if importBlock {
			imp := extractImportPath(trimmed, lang)
			if imp != "" {
				if isStdLibImport(imp, lang) {
					stdImports++
				} else {
					thirdPartyImports++
				}
			}
		}
	}

	if stdImports+thirdPartyImports < 3 {
		return FingerprintSignal{Name: "import-grouping", Value: 0, Weight: 0.08}
	}

	total := float64(stdImports + thirdPartyImports)
	thirdRatio := float64(thirdPartyImports) / total

	score := 50.0
	detail := ""
	if thirdRatio > 0.7 {
		score = 70.0
		detail = "High proportion of third-party imports — AI tends to use popular packages"
	} else if thirdRatio < 0.2 {
		score = 20.0
	}

	return FingerprintSignal{
		Name:   "import-grouping",
		Value:  score,
		Weight: 0.08,
		Detail: detail,
	}
}

func (f *Fingerprinter) errorHandlingVerbosity(lines []string, lang string) FingerprintSignal {
	errHandlingLines := 0
	totalLines := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isComment(trimmed, lang) {
			continue
		}
		totalLines++
		if isErrorHandling(trimmed, lang) {
			errHandlingLines++
		}
	}

	if totalLines == 0 {
		return FingerprintSignal{Name: "error-handling", Value: 0, Weight: 0.07}
	}

	ratio := float64(errHandlingLines) / float64(totalLines)
	score := ratio * 100

	detail := ""
	if ratio > 0.15 {
		detail = "Very high error handling density (>15%) — AI often over-handles errors"
	}

	return FingerprintSignal{
		Name:   "error-handling",
		Value:  score,
		Weight: 0.07,
		Detail: detail,
	}
}

func isComment(line, lang string) bool {
	if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "#") {
		return true
	}
	return false
}

func isFunctionDecl(line, lang string) bool {
	switch lang {
	case "go":
		return strings.HasPrefix(line, "func ") || strings.HasPrefix(line, "func (")
	case "python":
		return strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "async def ")
	case "javascript":
		return strings.HasPrefix(line, "function ") || strings.HasPrefix(line, "const ") || strings.HasPrefix(line, "let ") || strings.HasPrefix(line, "var ")
	default:
		return strings.HasPrefix(line, "func ") || strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "function ")
	}
}

func isSnakeCase(name string) bool {
	for _, r := range name {
		if unicode.IsUpper(r) {
			return false
		}
	}
	return strings.Contains(name, "_")
}

func isCamelCase(name string) bool {
	hasLower := false
	hasUpper := false
	for _, r := range name {
		if unicode.IsLower(r) {
			hasLower = true
		}
		if unicode.IsUpper(r) {
			hasUpper = true
		}
	}
	return hasLower && hasUpper && !strings.Contains(name, "_")
}

func isImportStart(line, lang string) bool {
	switch lang {
	case "go":
		return line == "import (" || line == "import"
	case "python":
		return strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "from ")
	case "javascript":
		return strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "const ") && strings.Contains(line, "require(")
	default:
		return false
	}
}

func isImportEnd(line, lang string) bool {
	return line == ")"
}

func extractImportPath(line, lang string) string {
	switch lang {
	case "go":
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "\"") || strings.HasPrefix(line, "	\"") {
			line = strings.TrimLeft(line, " \t")
			if idx := strings.LastIndex(line, "\""); idx > 0 {
				return line[1:idx]
			}
		}
	case "python":
		if strings.HasPrefix(line, "import ") {
			return strings.TrimPrefix(line, "import ")
		}
		if strings.HasPrefix(line, "from ") {
			parts := strings.Split(line, " ")
			if len(parts) > 1 {
				return parts[1]
			}
		}
	case "javascript":
		if strings.Contains(line, "from ") {
			parts := strings.Split(line, "from ")
			if len(parts) > 1 {
				return strings.Trim(strings.TrimSpace(parts[1]), "'\"")
			}
		}
	}
	return ""
}

func isStdLibImport(imp, lang string) bool {
	switch lang {
	case "go":
		return !strings.Contains(imp, ".")
	case "python":
		stdLibs := map[string]bool{"os": true, "sys": true, "json": true, "re": true, "math": true, "time": true, "pathlib": true, "collections": true, "functools": true, "itertools": true, "typing": true, "abc": true, "dataclasses": true, "enum": true, "hashlib": true, "hmac": true, "uuid": true, "datetime": true, "random": true}
		return stdLibs[strings.Split(imp, ".")[0]]
	default:
		return false
	}
}

func isErrorHandling(line, lang string) bool {
	lower := strings.ToLower(line)
	switch lang {
	case "go":
		return strings.Contains(lower, "if err") || strings.Contains(lower, "if err != nil") || strings.Contains(lower, "if err == nil") || strings.Contains(lower, "err != nil") || strings.Contains(lower, "return err") || strings.Contains(lower, "return fmt.errorf") || strings.Contains(lower, "errors.new(")
	case "python":
		return strings.Contains(lower, "try:") || strings.Contains(lower, "except ") || strings.Contains(lower, "raise ") || strings.Contains(lower, "finally:") || strings.Contains(lower, "valueerror") || strings.Contains(lower, "typeerror") || strings.Contains(lower, "keyerror")
	case "javascript":
		return strings.Contains(lower, "try ") || strings.Contains(lower, "catch(") || strings.Contains(lower, "catch (") || strings.Contains(lower, "throw ") || strings.Contains(lower, ".catch(") || strings.Contains(lower, "reject(")
	}
	return false
}

func formatFloat(f float64) string {
	return strings.TrimRight(strings.TrimRight(
		strings.Replace(
			strings.Replace(
				fmt.Sprintf("%.4f", f), "0000", "", -1),
			"000", "", -1),
		"0"), ".")
}
