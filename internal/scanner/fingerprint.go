package scanner

import (
	"math"
	"strings"
)

type Fingerprinter struct{}

type FingerprintResult struct {
	Score   int                 `json:"score"`
	Signals []FingerprintSignal `json:"signals"`
	Verdict string              `json:"verdict"`
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
	switch {
	case strings.HasSuffix(path, ".go"):
		return "go"
	case strings.HasSuffix(path, ".py"):
		return "python"
	case strings.HasSuffix(path, ".js"):
		return "javascript"
	case strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".tsx"):
		return "typescript"
	case strings.HasSuffix(path, ".jsx"):
		return "javascript"
	case strings.HasSuffix(path, ".java"):
		return "java"
	case strings.HasSuffix(path, ".rs"):
		return "rust"
	default:
		return "unknown"
	}
}

func (f *Fingerprinter) collectSignals(content, lang string) []FingerprintSignal {
	lines := strings.Split(content, "\n")
	return []FingerprintSignal{
		f.commentDensity(lines, lang),
		f.lineLengthUniformity(lines),
		f.docCoverage(lines, lang),
		f.functionLengthConsistency(content, lang),
		f.namingConventionConsistency(lines, lang),
		f.repeatedPatterns(lines),
		f.importGrouping(lines, lang),
		f.errorHandlingVerbosity(lines, lang),
	}
}
