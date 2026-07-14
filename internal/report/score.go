package report

import "github.com/WorldOccupier/trusty/internal/types"

type Reporter struct{}

func New() *Reporter {
	return &Reporter{}
}

func (r *Reporter) BuildResult(files []types.FileResult, summary types.ScanSummary, trustScore int, timestamp string, durationMs int64) types.ScanResult {
	return types.ScanResult{
		Files:      files,
		Summary:    summary,
		TrustScore: trustScore,
		Timestamp:  timestamp,
		DurationMs: durationMs,
	}
}

func CalculateScore(errors, warnings, infos int) int {
	score := 100 - (errors*15 + warnings*7 + infos*3)
	if score < 0 {
		score = 0
	}
	return score
}
