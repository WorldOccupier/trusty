package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/WorldOccupier/trusty/internal/types"
)

type Webhook struct {
	url    string
	client *http.Client
}

type slackMessage struct {
	Text        string       `json:"text"`
	Attachments []attachment `json:"attachments,omitempty"`
}

type attachment struct {
	Color  string  `json:"color"`
	Title  string  `json:"title"`
	Text   string  `json:"text"`
	Fields []field `json:"fields,omitempty"`
}

type field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func New(webhookURL string) *Webhook {
	if webhookURL == "" {
		webhookURL = os.Getenv("SLACK_WEBHOOK_URL")
	}
	return &Webhook{url: webhookURL, client: &http.Client{}}
}

func (w *Webhook) Post(result *types.ScanResult) error {
	if w.url == "" {
		return fmt.Errorf("SLACK_WEBHOOK_URL not set")
	}

	color := "#00FF88"
	if result.TrustScore < 70 {
		color = "#FFAA00"
	}
	if result.TrustScore < 50 {
		color = "#FF4444"
	}

	msg := slackMessage{
		Text: fmt.Sprintf("Trusty Scan Results — Score: %d/100", result.TrustScore),
		Attachments: []attachment{
			{
				Color: color,
				Title: "Summary",
				Text:  result.Summary.Status,
				Fields: []field{
					{Title: "Trust Score", Value: fmt.Sprintf("%d/100", result.TrustScore), Short: true},
					{Title: "Total Issues", Value: fmt.Sprintf("%d", result.Summary.TotalIssues), Short: true},
					{Title: "Errors", Value: fmt.Sprintf("%d", result.Summary.Errors), Short: true},
					{Title: "Warnings", Value: fmt.Sprintf("%d", result.Summary.Warnings), Short: true},
					{Title: "Files Scanned", Value: fmt.Sprintf("%d", result.Summary.FilesScanned), Short: true},
					{Title: "Duration", Value: fmt.Sprintf("%dms", result.DurationMs), Short: true},
				},
			},
		},
	}

	for _, f := range result.Files {
		if len(f.Findings) == 0 {
			continue
		}
		var fields []field
		for _, finding := range f.Findings {
			sev := "INFO"
			if finding.Severity == types.SeverityError {
				sev = "ERROR"
			} else if finding.Severity == types.SeverityWarning {
				sev = "WARN"
			}
			fields = append(fields, field{
				Title: fmt.Sprintf("%s:%d", f.Path, finding.Line),
				Value: fmt.Sprintf("[%s] %s", sev, finding.Message),
				Short: false,
			})
		}
		msg.Attachments = append(msg.Attachments, attachment{
			Color:  color,
			Title:  fmt.Sprintf("File: %s (%d finding(s))", f.Path, len(f.Findings)),
			Fields: fields,
		})
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	resp, err := w.client.Post(w.url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("posting to Slack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Slack API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
