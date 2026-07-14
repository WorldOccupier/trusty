package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/WorldOccupier/trusty/internal/types"
)

func WriteJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func FormatJSON(v interface{}) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling: %w", err)
	}
	return string(data), nil
}

func ParseResult(data []byte) *types.ScanResult {
	var r types.ScanResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil
	}
	return &r
}

func ParseResultFromFile(path string) (*types.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	r := ParseResult(data)
	if r == nil {
		return nil, fmt.Errorf("invalid scan result format")
	}
	return r, nil
}
