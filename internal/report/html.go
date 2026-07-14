package report

import (
	"fmt"
	"html"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

func FormatHTML(result types.ScanResult) (string, error) {
	var b strings.Builder

	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"UTF-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	b.WriteString(fmt.Sprintf("<title>Trusty Scan Report — %s</title>\n", result.Timestamp))
	b.WriteString("<style>\n")
	b.WriteString(htmlCSS())
	b.WriteString("</style>\n</head>\n<body>\n")

	writeHeader(&b, result)
	writeSummary(&b, result)
	writeFiles(&b, result)

	b.WriteString("</body>\n</html>\n")

	return b.String(), nil
}

func htmlCSS() string {
	return `
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
h1 { font-size: 24px; margin-bottom: 8px; }
h2 { font-size: 18px; margin: 24px 0 12px; }
.header { border-bottom: 1px solid #30363d; padding-bottom: 16px; margin-bottom: 24px; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
.stat-value { font-size: 28px; font-weight: 700; }
.stat-label { font-size: 12px; color: #8b949e; margin-top: 4px; }
.file-section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
.file-header { padding: 12px 16px; font-family: monospace; font-size: 14px; border-bottom: 1px solid #30363d; cursor: pointer; }
.file-header:hover { background: #1c2128; }
.file-findings { padding: 8px 16px 16px; }
.finding { padding: 8px 0; border-bottom: 1px solid #21262d; }
.finding:last-child { border-bottom: none; }
.finding-ERROR { border-left: 3px solid #f85149; padding-left: 12px; }
.finding-WARN { border-left: 3px solid #d29922; padding-left: 12px; }
.finding-INFO { border-left: 3px solid #58a6ff; padding-left: 12px; }
.finding-rule { font-family: monospace; font-size: 12px; color: #8b949e; }
.finding-message { margin: 4px 0; font-size: 14px; }
.finding-line { font-family: monospace; font-size: 12px; color: #8b949e; }
.finding-sev { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-right: 6px; }
.sev-ERROR { background: #f8514922; color: #f85149; }
.sev-WARN { background: #d2992222; color: #d29922; }
.sev-INFO { background: #58a6ff22; color: #58a6ff; }
.score-bar { height: 8px; border-radius: 4px; background: #21262d; margin-top: 8px; overflow: hidden; }
.score-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.score-pass { background: #3fb950; }
.score-warn { background: #d29922; }
.score-fail { background: #f85149; }
.empty { color: #8b949e; font-style: italic; padding: 16px; text-align: center; }
`
}

func writeHeader(b *strings.Builder, result types.ScanResult) {
	b.WriteString("<div class=\"header\">\n")
	b.WriteString(fmt.Sprintf("<h1>Trusty Scan Report</h1>\n"))
	b.WriteString(fmt.Sprintf("<p>Timestamp: %s | Duration: %dms</p>\n", result.Timestamp, result.DurationMs))
	b.WriteString("</div>\n")
}

func writeSummary(b *strings.Builder, result types.ScanResult) {
	scoreClass := "score-pass"
	if result.TrustScore < 70 {
		scoreClass = "score-fail"
	} else if result.TrustScore < 90 {
		scoreClass = "score-warn"
	}

	b.WriteString("<div class=\"summary-grid\">\n")
	writeStat(b, "Trust Score", fmt.Sprintf("%d/100", result.TrustScore), "")
	writeStat(b, "Files", fmt.Sprintf("%d", result.Summary.FilesScanned), "")
	writeStat(b, "Issues", fmt.Sprintf("%d", result.Summary.TotalIssues), "")
	writeStat(b, "Errors", fmt.Sprintf("%d", result.Summary.Errors), "sev-ERROR")
	writeStat(b, "Warnings", fmt.Sprintf("%d", result.Summary.Warnings), "sev-WARN")
	writeStat(b, "Info", fmt.Sprintf("%d", result.Summary.Info), "sev-INFO")
	b.WriteString("</div>\n")

	b.WriteString(fmt.Sprintf("<div class=\"score-bar\"><div class=\"score-fill %s\" style=\"width:%d%%\"></div></div>\n", scoreClass, result.TrustScore))
}

func writeStat(b *strings.Builder, label, value, sevClass string) {
	b.WriteString("<div class=\"stat-card\">")
	if sevClass != "" {
		b.WriteString(fmt.Sprintf("<div class=\"stat-value %s\">%s</div>", sevClass, value))
	} else {
		b.WriteString(fmt.Sprintf("<div class=\"stat-value\">%s</div>", html.EscapeString(value)))
	}
	b.WriteString(fmt.Sprintf("<div class=\"stat-label\">%s</div>", html.EscapeString(label)))
	b.WriteString("</div>\n")
}

func writeFiles(b *strings.Builder, result types.ScanResult) {
	if len(result.Files) == 0 {
		b.WriteString("<div class=\"empty\">No files scanned — all clear</div>\n")
		return
	}

	for _, file := range result.Files {
		if len(file.Findings) == 0 {
			continue
		}

		b.WriteString("<div class=\"file-section\">\n")
		b.WriteString(fmt.Sprintf("<div class=\"file-header\">%s <span style=\"color:#8b949e;font-size:12px\">(%s, score: %d/100)</span></div>\n",
			html.EscapeString(file.Path), html.EscapeString(file.Language), file.Score))
		b.WriteString("<div class=\"file-findings\">\n")

		for _, f := range file.Findings {
			sev := "INFO"
			sevClass := "sev-INFO"
			switch f.Severity {
			case types.SeverityError:
				sev = "ERROR"
				sevClass = "sev-ERROR"
			case types.SeverityWarning:
				sev = "WARN"
				sevClass = "sev-WARN"
			}

			b.WriteString(fmt.Sprintf("<div class=\"finding finding-%s\">\n", sev))
			b.WriteString(fmt.Sprintf("<div><span class=\"finding-sev %s\">%s</span><span class=\"finding-rule\">%s</span></div>\n",
				sevClass, sev, html.EscapeString(f.Rule)))
			b.WriteString(fmt.Sprintf("<div class=\"finding-message\">%s</div>\n", html.EscapeString(f.Message)))
			if f.Line > 0 {
				b.WriteString(fmt.Sprintf("<div class=\"finding-line\">Line %d", f.Line))
				if f.Suggestion != "" {
					b.WriteString(fmt.Sprintf(" — %s", html.EscapeString(f.Suggestion)))
				}
				b.WriteString("</div>\n")
			}
			b.WriteString("</div>\n")
		}

		b.WriteString("</div>\n</div>\n")
	}
}
