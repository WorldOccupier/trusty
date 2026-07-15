package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFindGoMods_WithModFile(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(goMod, []byte("module test\n"), 0644); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}

	mods, err := FindGoMods(dir)
	if err != nil {
		t.Fatalf("FindGoMods() failed: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("expected 1 go.mod, got %d", len(mods))
	}
	if mods[0] != goMod {
		t.Errorf("expected %s, got %s", goMod, mods[0])
	}
}

func TestFindGoMods_NoModFile(t *testing.T) {
	dir := t.TempDir()
	mods, err := FindGoMods(dir)
	if err != nil {
		t.Fatalf("FindGoMods() failed: %v", err)
	}
	if len(mods) != 0 {
		t.Fatalf("expected 0 go.mod files, got %d", len(mods))
	}
}

func TestFindGoMods_Subdirectory(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	subMod := filepath.Join(subdir, "go.mod")
	if err := os.WriteFile(subMod, []byte("module sub\n"), 0644); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}

	mods, err := FindGoMods(dir)
	if err != nil {
		t.Fatalf("FindGoMods() failed: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("expected 1 go.mod, got %d", len(mods))
	}
}

func TestFindGoMods_SkipsHiddenDirs(t *testing.T) {
	dir := t.TempDir()
	hidden := filepath.Join(dir, ".hidden")
	if err := os.Mkdir(hidden, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	hiddenMod := filepath.Join(hidden, "go.mod")
	if err := os.WriteFile(hiddenMod, []byte("module hidden\n"), 0644); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}

	mods, err := FindGoMods(dir)
	if err != nil {
		t.Fatalf("FindGoMods() failed: %v", err)
	}
	if len(mods) != 0 {
		t.Fatalf("expected 0 go.mod (hidden dir skipped), got %d", len(mods))
	}
}

func TestGenerateFromGoSum_Valid(t *testing.T) {
	dir := t.TempDir()
	sumFile := filepath.Join(dir, "go.sum")
	content := `github.com/spf13/cobra v1.10.2 h1:abcdef1234567890
github.com/spf13/pflag v1.0.9 h1:0987654321
gopkg.in/yaml.v3 v3.0.1 h1:abcd1234567890`
	if err := os.WriteFile(sumFile, []byte(content), 0644); err != nil {
		t.Fatalf("writing go.sum: %v", err)
	}

	bomBytes, err := GenerateFromGoSum(sumFile)
	if err != nil {
		t.Fatalf("GenerateFromGoSum() failed: %v", err)
	}

	var bom CycloneDXBom
	if err := json.Unmarshal(bomBytes, &bom); err != nil {
		t.Fatalf("unmarshaling BOM: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("expected CycloneDX, got %q", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.5" {
		t.Errorf("expected spec 1.5, got %q", bom.SpecVersion)
	}
	if bom.Version != 1 {
		t.Errorf("expected version 1, got %d", bom.Version)
	}
	if len(bom.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(bom.Components))
	}

	expectedNames := map[string]bool{
		"github.com/spf13/cobra": false,
		"github.com/spf13/pflag":  false,
		"gopkg.in/yaml.v3":       false,
	}
	for _, comp := range bom.Components {
		if comp.Type != "library" {
			t.Errorf("expected type 'library', got %q", comp.Type)
		}
		if _, ok := expectedNames[comp.Name]; ok {
			expectedNames[comp.Name] = true
		}
	}
	for name, found := range expectedNames {
		if !found {
			t.Errorf("component %q not found in BOM", name)
		}
	}
}

func TestGenerateFromGoSum_MissingFile(t *testing.T) {
	_, err := GenerateFromGoSum("/tmp/nonexistent-gosum-file-12345.sum")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestGenerateFromGoSum_Empty(t *testing.T) {
	dir := t.TempDir()
	sumFile := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(sumFile, []byte(""), 0644); err != nil {
		t.Fatalf("writing go.sum: %v", err)
	}

	bomBytes, err := GenerateFromGoSum(sumFile)
	if err != nil {
		t.Fatalf("GenerateFromGoSum() failed: %v", err)
	}

	var bom CycloneDXBom
	if err := json.Unmarshal(bomBytes, &bom); err != nil {
		t.Fatalf("unmarshaling BOM: %v", err)
	}
	if len(bom.Components) != 0 {
		t.Fatalf("expected 0 components for empty go.sum, got %d", len(bom.Components))
	}
}

func TestGenerateFromGoSum_Deduplicates(t *testing.T) {
	dir := t.TempDir()
	sumFile := filepath.Join(dir, "go.sum")
	content := `github.com/foo/bar v1.0.0 h1:abc
github.com/foo/bar v1.0.0 h1:abc`
	if err := os.WriteFile(sumFile, []byte(content), 0644); err != nil {
		t.Fatalf("writing go.sum: %v", err)
	}

	bomBytes, err := GenerateFromGoSum(sumFile)
	if err != nil {
		t.Fatalf("GenerateFromGoSum() failed: %v", err)
	}

	var bom CycloneDXBom
	if err := json.Unmarshal(bomBytes, &bom); err != nil {
		t.Fatalf("unmarshaling BOM: %v", err)
	}
	if len(bom.Components) != 1 {
		t.Fatalf("expected 1 deduplicated component, got %d", len(bom.Components))
	}
}

func TestGenerateFromGoModBytes_Valid(t *testing.T) {
	data := []byte(`module:
  path: github.com/test/mod
go: "1.24"
require:
- path: github.com/spf13/cobra
  version: v1.10.2
- path: gopkg.in/yaml.v3
  version: v3.0.1
`)
	bomBytes, err := GenerateFromGoModBytes(data)
	if err != nil {
		t.Fatalf("GenerateFromGoModBytes() failed: %v", err)
	}

	var bom CycloneDXBom
	if err := json.Unmarshal(bomBytes, &bom); err != nil {
		t.Fatalf("unmarshaling BOM: %v", err)
	}
	if len(bom.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(bom.Components))
	}
}

func TestGenerateFromGoModBytes_Invalid(t *testing.T) {
	_, err := GenerateFromGoModBytes([]byte("not: yaml: content: [[["))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestGenerateFromGoModBytes_Empty(t *testing.T) {
	bomBytes, err := GenerateFromGoModBytes([]byte(""))
	if err != nil {
		t.Fatalf("GenerateFromGoModBytes() failed: %v", err)
	}
	var bom CycloneDXBom
	if err := json.Unmarshal(bomBytes, &bom); err != nil {
		t.Fatalf("unmarshaling BOM: %v", err)
	}
	if len(bom.Components) != 0 {
		t.Fatalf("expected 0 components, got %d", len(bom.Components))
	}
}

func TestGuessLicense(t *testing.T) {
	tests := []struct {
		path    string
		want    string
	}{
		{"github.com/spf13/cobra", "Apache-2.0"},
		{"github.com/spf13/viper", "Apache-2.0"},
		{"github.com/spf13/pflag", "Apache-2.0"},
		{"gopkg.in/yaml.v3", "MIT"},
		{"github.com/go-yaml/yaml", "MIT"},
		{"github.com/fsnotify/fsnotify", "BSD-3-Clause"},
		{"github.com/charmbracelet/bubbletea", "MIT"},
		{"github.com/some/random", ""},
	}
	for _, tt := range tests {
		got := guessLicense(tt.path)
		if got != tt.want {
			t.Errorf("guessLicense(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestGenerateGoSBOM_MissingFile(t *testing.T) {
	_, err := GenerateGoSBOM("/tmp/nonexistent-dir-12345")
	if err == nil {
		t.Fatal("expected error for missing go.mod")
	}
}

func TestHasGoBinary(t *testing.T) {
	// This verifies the function runs without error
	_ = HasGoBinary()
}
