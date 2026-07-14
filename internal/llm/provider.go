package llm

import "context"

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

type Finding struct {
	Rule       string
	Severity   Severity
	Message    string
	Line       int
	Column     int
	Suggestion string
	Category   string
}

type AnalysisRequest struct {
	FilePath    string
	Language    string
	DiffContent string
	FullContent string
	Context     string
}

type AnalysisResponse struct {
	Findings []Finding
	Summary  string
}

type Provider interface {
	AnalyzeCode(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error)
	Name() string
}

type ProviderConfig struct {
	Model       string
	Temperature float64
	APIKey      string
	BaseURL     string
}

func NewProvider(name string, cfg ProviderConfig) Provider {
	switch name {
	case "openai":
		return &OpenAIProvider{config: cfg}
	case "ollama":
		return &OllamaProvider{config: cfg}
	case "anthropic":
		return &AnthropicProvider{config: cfg}
	default:
		return &OpenAIProvider{config: cfg}
	}
}
