package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/user/trustpilot/internal/types"
)

type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool       SARIFTool              `json:"tool"`
	Results    []SARIFResult          `json:"results"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription SARIFMessage `json:"shortDescription"`
	DefaultLevel     string       `json:"defaultLevel"`
}

type SARIFResult struct {
	RuleID    string                 `json:"ruleId"`
	Level     string                 `json:"level"`
	Message   SARIFMessage           `json:"message"`
	Locations []SARIFLocation        `json:"locations,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func WriteSARIF(w io.Writer, result *types.ScanResult) error {
	rulesMap := make(map[string]bool)
	var sarifResults []SARIFResult

	for _, file := range result.Files {
		for _, finding := range file.Findings {
			rulesMap[finding.Rule] = true

			level := "warning"
			switch finding.Severity {
			case types.SeverityError:
				level = "error"
			case types.SeverityInfo:
				level = "note"
			}

			sarifResult := SARIFResult{
				RuleID:  finding.Rule,
				Level:   level,
				Message: SARIFMessage{Text: finding.Message},
			}

			if finding.Line > 0 {
				sarifResult.Locations = []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: file.Path},
						Region: SARIFRegion{
							StartLine:   finding.Line,
							StartColumn: finding.Column,
						},
					},
				}}
			}

			sarifResults = append(sarifResults, sarifResult)
		}
	}

	var ruleList []SARIFRule
	for ruleID := range rulesMap {
		ruleList = append(ruleList, SARIFRule{
			ID:               ruleID,
			Name:             ruleID,
			ShortDescription: SARIFMessage{Text: ruleID},
			DefaultLevel:     "warning",
		})
	}

	log := SARIFLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "TrustPilot",
					InformationURI: "https://github.com/user/trustpilot",
					Rules:          ruleList,
				},
			},
			Results: sarifResults,
			Properties: map[string]interface{}{
				"trustScore": result.TrustScore,
				"summary":    result.Summary,
			},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func NewSARIFLog(result *types.ScanResult) (*SARIFLog, error) {
	return &SARIFLog{}, fmt.Errorf("use WriteSARIF instead")
}
