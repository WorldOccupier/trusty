package scanner

import (
	"math"
	"strings"
)
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

