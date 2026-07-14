package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type HistoryEntry struct {
	Timestamp  string `json:"timestamp"`
	TrustScore int    `json:"trust_score"`
	TotalIssues int   `json:"total_issues"`
	Errors     int    `json:"errors"`
	Warnings   int    `json:"warnings"`
	Infos      int    `json:"infos"`
	FilesCount int    `json:"files_count"`
}

type History struct {
	Entries  []HistoryEntry `json:"entries"`
	filePath string
}

func LoadHistory(path string) *History {
	h := &History{filePath: path}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return h
	}
	json.Unmarshal(data, h)
	if h.Entries == nil {
		h.Entries = []HistoryEntry{}
	}
	return h
}

func (h *History) Record(score int, totalIssues, errors, warnings, infos, filesCount int) HistoryEntry {
	entry := HistoryEntry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		TrustScore:  score,
		TotalIssues: totalIssues,
		Errors:      errors,
		Warnings:    warnings,
		Infos:       infos,
		FilesCount:  filesCount,
	}
	h.Entries = append(h.Entries, entry)
	return entry
}

func (h *History) Save() error {
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling history: %w", err)
	}
	return os.WriteFile(filepath.Clean(h.filePath), data, 0644)
}

func (h *History) Compare(entry HistoryEntry) string {
	if len(h.Entries) < 2 {
		return ""
	}
	prev := h.Entries[len(h.Entries)-2]

	var changes []string
	if entry.TrustScore < prev.TrustScore {
		changes = append(changes, fmt.Sprintf("trust score dropped %d→%d", prev.TrustScore, entry.TrustScore))
	}
	if entry.TotalIssues > prev.TotalIssues {
		changes = append(changes, fmt.Sprintf("issues increased %d→%d (+%d)", prev.TotalIssues, entry.TotalIssues, entry.TotalIssues-prev.TotalIssues))
	}
	if entry.Errors > prev.Errors {
		changes = append(changes, fmt.Sprintf("errors increased %d→%d (+%d)", prev.Errors, entry.Errors, entry.Errors-prev.Errors))
	}

	if len(changes) == 0 {
		return "No regressions detected."
	}
	return "Regressions detected: " + stringsJoin(changes, ", ")
}

func stringsJoin(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	result := elems[0]
	for _, e := range elems[1:] {
		result += sep + e
	}
	return result
}
