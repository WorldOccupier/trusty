package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/WorldOccupier/trusty/internal/audit"
)

type DashboardData struct {
	TotalScans   int            `json:"total_scans"`
	AvgScore     int            `json:"avg_score"`
	TotalIssues  int            `json:"total_issues"`
	RecentScans  []audit.Entry  `json:"recent_scans"`
	ScoreHistory []ScorePoint   `json:"score_history"`
}

type ScorePoint struct {
	Timestamp string `json:"timestamp"`
	Score     int    `json:"score"`
	Issues    int    `json:"issues"`
}

const dashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Trusty Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
h1 { color: #00FF88; font-size: 28px; margin-bottom: 24px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
.card h3 { color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
.card .value { font-size: 32px; font-weight: bold; }
.chart-container { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 32px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 12px 16px; border-bottom: 1px solid #21262d; }
th { color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
td { font-size: 14px; }
.status-clean { color: #00FF88; }
.status-warning { color: #FFAA00; }
.status-failed { color: #FF4444; }
</style>
</head>
<body>
<h1>Trusty Dashboard</h1>
<div class="cards">
<div class="card"><h3>Total Scans</h3><div class="value">{{.TotalScans}}</div></div>
<div class="card"><h3>Average Score</h3><div class="value">{{.AvgScore}}/100</div></div>
<div class="card"><h3>Total Issues</h3><div class="value">{{.TotalIssues}}</div></div>
</div>
<div class="chart-container">
<canvas id="scoreChart" height="100"></canvas>
</div>
<h2>Recent Scans</h2>
<table>
<thead><tr><th>Time</th><th>User</th><th>Command</th><th>Score</th><th>Issues</th><th>Status</th></tr></thead>
<tbody>
{{range .RecentScans}}
<tr>
<td>{{.Timestamp}}</td>
<td>{{.User}}</td>
<td>{{.Command}}</td>
<td>{{.TrustScore}}/100</td>
<td>{{.TotalIssues}}</td>
<td class="status-{{.Status}}">{{.Status}}</td>
</tr>
{{end}}
</tbody>
</table>
<script>
const ctx = document.getElementById('scoreChart').getContext('2d');
new Chart(ctx, {
type: 'line',
data: {
labels: [{{range $i, $s := .ScoreHistory}}{{if $i}},{{end}}'{{$s.Timestamp}}'{{end}}],
datasets: [{
label: 'Trust Score',
data: [{{range $i, $s := .ScoreHistory}}{{if $i}},{{end}}{{$s.Score}}{{end}}],
borderColor: '#00FF88',
backgroundColor: 'rgba(0, 255, 136, 0.1)',
fill: true,
tension: 0.3
}]
},
options: {
responsive: true,
plugins: { legend: { labels: { color: '#8b949e' } } },
scales: {
x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
y: { min: 0, max: 100, ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }
}
}
});
</script>
</body>
</html>`

func Generate(auditPath string) (string, error) {
	trail := audit.New(auditPath)
	totalScans, avgScore, totalIssues, err := trail.Summary()
	if err != nil {
		return "", fmt.Errorf("reading audit trail: %w", err)
	}

	recent, err := trail.Query(20, "", "")
	if err != nil {
		return "", err
	}

	var history []ScorePoint
	for i := len(recent) - 1; i >= 0; i-- {
		e := recent[i]
		ts := e.Timestamp
		if len(ts) > 10 {
			ts = ts[:10]
		}
		history = append(history, ScorePoint{Timestamp: ts, Score: e.TrustScore, Issues: e.TotalIssues})
	}

	data := DashboardData{
		TotalScans:   totalScans,
		AvgScore:     avgScore,
		TotalIssues:  totalIssues,
		RecentScans:  recent,
		ScoreHistory: history,
	}

	tmpl, err := template.New("dashboard").Parse(dashboardTemplate)
	if err != nil {
		return "", fmt.Errorf("parsing template: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("rendering dashboard: %w", err)
	}

	return buf.String(), nil
}

func WriteToFile(auditPath, outputPath string) error {
	html, err := Generate(auditPath)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Clean(outputPath), []byte(html), 0644)
}

func WriteJSON(auditPath string) (string, error) {
	trail := audit.New(auditPath)
	totalScans, avgScore, totalIssues, err := trail.Summary()
	if err != nil {
		return "", err
	}
	recent, err := trail.Query(20, "", "")
	if err != nil {
		return "", err
	}
	data := DashboardData{
		TotalScans:  totalScans,
		AvgScore:    avgScore,
		TotalIssues: totalIssues,
		RecentScans: recent,
	}
	result, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}
