package ci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

func buildCommentBody(result *types.ScanResult, platform string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## Trusty Scan Results (%s)\n\n", platform))
	sb.WriteString(fmt.Sprintf("**Trust Score:** %d/100 | **Issues:** %d | **Status:** %s\n\n",
		result.TrustScore, result.Summary.TotalIssues, result.Summary.Status))

	if result.Summary.TotalIssues == 0 {
		sb.WriteString(":white_check_mark: No issues found.\n")
		return sb.String()
	}

	sb.WriteString("| Metric | Value |\n|---|---|\n")
	sb.WriteString(fmt.Sprintf("| Trust Score | %d/100 |\n", result.TrustScore))
	sb.WriteString(fmt.Sprintf("| Total Issues | %d |\n", result.Summary.TotalIssues))
	sb.WriteString(fmt.Sprintf("| Errors | %d |\n", result.Summary.Errors))
	sb.WriteString(fmt.Sprintf("| Warnings | %d |\n", result.Summary.Warnings))
	sb.WriteString(fmt.Sprintf("| Files Scanned | %d |\n", result.Summary.FilesScanned))
	sb.WriteString(fmt.Sprintf("| Duration | %dms |\n\n", result.DurationMs))

	for _, f := range result.Files {
		if len(f.Findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("### %s\n\n", f.Path))
		sb.WriteString("| Severity | Rule | Line | Message |\n|---|---|---|---|\n")
		for _, finding := range f.Findings {
			sev := "INFO"
			if finding.Severity == types.SeverityError {
				sev = "ERROR"
			} else if finding.Severity == types.SeverityWarning {
				sev = "WARN"
			}
			msg := strings.ReplaceAll(finding.Message, "|", "\\|")
			sb.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n", sev, finding.Rule, finding.Line, msg))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func postComment(token, repoOrProject, id, body, platform string) error {
	var url string
	if platform == "github" {
		url = fmt.Sprintf("https://api.github.com/repos/%s/issues/%s/comments", repoOrProject, id)
	} else {
		host := os.Getenv("CI_SERVER_URL")
		if host == "" {
			host = "https://gitlab.com"
		}
		url = fmt.Sprintf("%s/api/v4/projects/%s/merge_requests/%s/notes",
			strings.TrimRight(host, "/"), repoOrProject, id)
	}

	payload := map[string]string{"body": body}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	if platform == "github" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
	} else {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("posting comment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
