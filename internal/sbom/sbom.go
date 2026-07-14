package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type GoModule struct {
	Path    string `yaml:"path"`
	Version string `yaml:"version"`
	Indirect bool  `yaml:"indirect,omitempty"`
}

type GoMod struct {
	Module  GoModule   `yaml:"module"`
	Go      string     `yaml:"go"`
	Require []GoModule `yaml:"require"`
}

type CycloneDXBom struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Components  []CycloneDXComponent `json:"components"`
}

type CycloneDXComponent struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Licenses   []License `json:"licenses,omitempty"`
}

type License struct {
	ID string `json:"id"`
}

func GenerateGoSBOM(path string) ([]byte, error) {
	goModPath := filepath.Join(path, "go.mod")
	data, err := os.ReadFile(filepath.Clean(goModPath))
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	var mod GoMod
	if err := yaml.Unmarshal(data, &mod); err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	components := []CycloneDXComponent{}

	for _, dep := range mod.Require {
		comp := CycloneDXComponent{
			Type:    "library",
			Name:    dep.Path,
			Version: dep.Version,
		}

		license := guessLicense(dep.Path)
		if license != "" {
			comp.Licenses = []License{{ID: license}}
		}
		components = append(components, comp)
	}

	bom := CycloneDXBom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  components,
	}

	return json.MarshalIndent(bom, "", "  ")
}

func GenerateFromGoModBytes(data []byte) ([]byte, error) {
	var mod GoMod
	if err := yaml.Unmarshal(data, &mod); err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}
	components := []CycloneDXComponent{}
	for _, dep := range mod.Require {
		comp := CycloneDXComponent{
			Type:    "library",
			Name:    dep.Path,
			Version: dep.Version,
		}
		license := guessLicense(dep.Path)
		if license != "" {
			comp.Licenses = []License{{ID: license}}
		}
		components = append(components, comp)
	}
	bom := CycloneDXBom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  components,
	}
	return json.MarshalIndent(bom, "", "  ")
}

func GenerateFromGoSum(path string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading go.sum: %w", err)
	}

	modules := parseGoSum(string(data))
	components := []CycloneDXComponent{}
	for _, m := range modules {
		comp := CycloneDXComponent{
			Type:    "library",
			Name:    m.path,
			Version: m.version,
		}
		license := guessLicense(m.path)
		if license != "" {
			comp.Licenses = []License{{ID: license}}
		}
		components = append(components, comp)
	}

	bom := CycloneDXBom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  components,
	}
	return json.MarshalIndent(bom, "", "  ")
}

type goSumModule struct {
	path    string
	version string
}

func parseGoSum(content string) []goSumModule {
	var modules []goSumModule
	seen := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := parts[0] + "@" + parts[1]
			if !seen[key] {
				seen[key] = true
				modules = append(modules, goSumModule{path: parts[0], version: parts[1]})
			}
		}
	}
	return modules
}

func guessLicense(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		switch parts[len(parts)-1] {
		case "cobra", "viper", "pflag":
			return "Apache-2.0"
		case "yaml", "yaml.v3":
			return "MIT"
		case "fsnotify":
			return "BSD-3-Clause"
		case "bubbletea":
			return "MIT"
		}
	}
	return ""
}

func FindGoMods(root string) ([]string, error) {
	var mods []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") && path != root {
			return filepath.SkipDir
		}
		if info.Name() == "go.mod" {
			mods = append(mods, path)
		}
		return nil
	})
	return mods, err
}

func HasGoBinary() bool {
	cmd := exec.Command("go", "version")
	return cmd.Run() == nil
}
