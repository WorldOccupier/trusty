package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Entry struct {
	Timestamp    string `json:"timestamp"`
	User         string `json:"user"`
	Commit       string `json:"commit,omitempty"`
	Command      string `json:"command"`
	FilesScanned int    `json:"files_scanned"`
	TotalIssues  int    `json:"total_issues"`
	TrustScore   int    `json:"trust_score"`
	Errors       int    `json:"errors"`
	Warnings     int    `json:"warnings"`
	Infos        int    `json:"infos"`
	Status       string `json:"status"`
}

type Trail struct {
	path string
}

func New(path string) *Trail {
	if path == "" {
		path = ".trusty-audit.jsonl"
	}
	return &Trail{path: path}
}

func (t *Trail) Record(command string, filesScanned, totalIssues, trustScore, errors, warnings, infos int, status string) (Entry, error) {
	entry := Entry{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		User:         gitConfig("user.name"),
		Commit:       gitRevParse("HEAD"),
		Command:      command,
		FilesScanned: filesScanned,
		TotalIssues:  totalIssues,
		TrustScore:   trustScore,
		Errors:       errors,
		Warnings:     warnings,
		Infos:        infos,
		Status:       status,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return entry, fmt.Errorf("marshaling audit entry: %w", err)
	}

	f, err := os.OpenFile(filepath.Clean(t.path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return entry, fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, string(data)); err != nil {
		return entry, fmt.Errorf("writing audit entry: %w", err)
	}

	return entry, nil
}

func (t *Trail) Query(limit int, status string, since string) ([]Entry, error) {
	f, err := os.Open(filepath.Clean(t.path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	sinceTime := time.Time{}
	if since != "" {
		sinceTime, _ = time.Parse(time.RFC3339, since)
	}

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if status != "" && e.Status != status {
			continue
		}
		if !sinceTime.IsZero() {
			t, err := time.Parse(time.RFC3339, e.Timestamp)
			if err != nil || t.Before(sinceTime) {
				continue
			}
		}
		entries = append(entries, e)
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	return entries, scanner.Err()
}

func (t *Trail) Summary() (totalScans int, avgScore int, totalIssues int, err error) {
	entries, err := t.Query(0, "", "")
	if err != nil {
		return 0, 0, 0, err
	}
	if len(entries) == 0 {
		return 0, 0, 0, nil
	}
	scoreSum := 0
	issueSum := 0
	for _, e := range entries {
		scoreSum += e.TrustScore
		issueSum += e.TotalIssues
	}
	return len(entries), scoreSum / len(entries), issueSum, nil
}

func gitConfig(key string) string {
	cmd := exec.Command("git", "config", "--get", key)
	out, err := cmd.Output()
	if err != nil {
		return os.Getenv("USER")
	}
	return strings.TrimSpace(string(out))
}

func gitRevParse(ref string) string {
	cmd := exec.Command("git", "rev-parse", ref)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
