package types

type Severity int

const (
	SeverityError   Severity = 3
	SeverityWarning Severity = 2
	SeverityInfo    Severity = 1
)

type Finding struct {
	Rule       string   `json:"rule"`
	Severity   Severity `json:"severity"`
	Message    string   `json:"message"`
	Line       int      `json:"line,omitempty"`
	Column     int      `json:"column,omitempty"`
	Suggestion string   `json:"suggestion,omitempty"`
	Category   string   `json:"category"`
}

type FileResult struct {
	Path     string    `json:"path"`
	Language string    `json:"language"`
	Findings []Finding `json:"findings"`
	Score    int       `json:"score"`
}

type ScanSummary struct {
	TotalIssues  int    `json:"total_issues"`
	Errors       int    `json:"errors"`
	Warnings     int    `json:"warnings"`
	Info         int    `json:"info"`
	FilesScanned int    `json:"files_scanned"`
	Duration     string `json:"duration"`
	Status       string `json:"status"`
	MinScore     int    `json:"min_score"`
}

type ScanResult struct {
	Files      []FileResult `json:"files"`
	Summary    ScanSummary  `json:"summary"`
	TrustScore int          `json:"trust_score"`
	Timestamp  string       `json:"timestamp"`
	DurationMs int64        `json:"duration_ms"`
}

type DiffFile struct {
	Path     string
	Language string
	Diff     string
	Content  string
}

type DiffOptions struct {
	Staged    bool
	From      string
	To        string
	Base      string
	Head      string
	Path      string
	RawDiff   string
	ScanDir   string
	ScanPaths []string
}
