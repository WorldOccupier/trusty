package hallucination

import (
	"fmt"
	"go/parser"
	"go/token"
	"regexp"
	"strings"

	"github.com/user/trustpilot/internal/types"
)

type Detector struct {
	registry *Registry
}

func NewDetector() *Detector {
	return &Detector{
		registry: NewRegistry(),
	}
}

func (d *Detector) Detect(path, content, diff string) []types.Finding {
	if path == "" && content == "" {
		return nil
	}

	lang := detectLanguageFromPath(path)
	switch lang {
	case "go":
		return d.detectGo(path, content)
	case "python":
		return d.detectPython(content)
	case "typescript", "javascript":
		return d.detectJavaScript(content)
	default:
		return nil
	}
}

func (d *Detector) detectGo(path, content string) []types.Finding {
	var findings []types.Finding

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, content, parser.ImportsOnly)
	if err != nil {
		return nil
	}

	var localModule string
	if strings.Contains(content, "module ") {
		re := regexp.MustCompile(`module\s+(\S+)`)
		if m := re.FindStringSubmatch(content); len(m) > 1 {
			localModule = m[1]
		}
	}

	for _, imp := range f.Imports {
		importPath := strings.Trim(imp.Path.Value, "\"")
		pos := fset.Position(imp.Pos())

		if strings.HasPrefix(importPath, localModule) || isWellKnown(importPath) {
			continue
		}

		if isStdLib(importPath) {
			continue
		}

		if strings.Contains(importPath, ".") || strings.Contains(importPath, "/") {
			exists := d.registry.CheckGoModule(importPath)
			if !exists {
				findings = append(findings, types.Finding{
					Rule:       "hallucinated-import",
					Severity:   types.SeverityError,
					Message:    fmt.Sprintf("Import %q may not exist — could not verify in Go module proxy", importPath),
					Line:       pos.Line,
					Column:     pos.Column,
					Suggestion: fmt.Sprintf("Verify %q exists and is spelled correctly", importPath),
					Category:   "hallucination",
				})
			}
		}
	}

	return findings
}

func (d *Detector) detectPython(content string) []types.Finding {
	var findings []types.Finding

	importRe := regexp.MustCompile(`(?:from\s+(\S+)\s+import|\bimport\s+(\S+))`)
	matches := importRe.FindAllStringSubmatch(content, -1)

	for _, m := range matches {
		moduleName := m[1]
		if moduleName == "" {
			moduleName = m[2]
		}

		moduleName = strings.Split(moduleName, " ")[0]
		moduleName = strings.Split(moduleName, ",")[0]

		if moduleName == "" || strings.HasPrefix(moduleName, ".") || isWellKnownPython(moduleName) {
			continue
		}

		findings = append(findings, types.Finding{
			Rule:       "hallucinated-import",
			Severity:   types.SeverityError,
			Message:    fmt.Sprintf("Python module %q may not exist", moduleName),
			Suggestion: fmt.Sprintf("Verify %q is installed or spelled correctly", moduleName),
			Category:   "hallucination",
		})
	}

	return findings
}

func (d *Detector) detectJavaScript(content string) []types.Finding {
	var findings []types.Finding

	importRe := regexp.MustCompile(`(?:from\s+['"](\S+)['"]|require\(['"](\S+)['"]\))`)
	matches := importRe.FindAllStringSubmatch(content, -1)

	for _, m := range matches {
		moduleName := m[1]
		if moduleName == "" {
			moduleName = m[2]
		}

		if moduleName == "" || strings.HasPrefix(moduleName, ".") || strings.HasPrefix(moduleName, "/") || isWellKnownJS(moduleName) {
			continue
		}

		findings = append(findings, types.Finding{
			Rule:       "hallucinated-import",
			Severity:   types.SeverityError,
			Message:    fmt.Sprintf("npm package %q may not exist", moduleName),
			Suggestion: fmt.Sprintf("Verify %q is in package.json or spelled correctly", moduleName),
			Category:   "hallucination",
		})
	}

	return findings
}

func detectLanguageFromPath(path string) string {
	ext := ""
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		ext = strings.ToLower(path[idx:])
	}
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	default:
		return "unknown"
	}
}

func isWellKnown(importPath string) bool {
	known := []string{
		"github.com/spf13/cobra", "github.com/gin-gonic/gin",
		"github.com/gorilla/mux", "github.com/stretchr/testify",
		"github.com/prometheus/client_golang",
		"k8s.io/client-go", "k8s.io/api",
	}
	for _, k := range known {
		if strings.HasPrefix(importPath, k) {
			return true
		}
	}
	return false
}

func isWellKnownPython(module string) bool {
	known := map[string]bool{
		"os": true, "sys": true, "json": true, "re": true,
		"math": true, "time": true, "random": true, "collections": true,
		"itertools": true, "functools": true, "pathlib": true,
		"typing": true, "dataclasses": true, "enum": true,
		"requests": true, "flask": true, "django": true, "numpy": true,
		"pandas": true, "pytest": true, "sqlalchemy": true,
		"fastapi": true, "pydantic": true, "click": true,
	}
	return known[module]
}

func isWellKnownJS(module string) bool {
	known := map[string]bool{
		"react": true, "vue": true, "express": true, "lodash": true,
		"axios": true, "chalk": true, "commander": true, "inquirer": true,
		"fs-extra": true, "moment": true, "date-fns": true,
		"next": true, "nuxt": true, "typescript": true,
		"uuid": true, "dotenv": true, "cors": true, "body-parser": true,
	}
	return known[module]
}

func isStdLib(path string) bool {
	stdlibs := map[string]bool{
		"fmt": true, "os": true, "strings": true, "net/http": true,
		"encoding/json": true, "io": true, "time": true, "context": true,
		"sync": true, "errors": true, "math": true, "sort": true,
		"strconv": true, "regexp": true, "bytes": true, "bufio": true,
		"log": true, "flag": true, "reflect": true, "testing": true,
		"database/sql": true, "crypto/tls": true, "net": true,
		"path": true, "path/filepath": true, "io/ioutil": true,
		"os/exec": true, "encoding": true, "archive/tar": true,
		"archive/zip": true, "compress/gzip": true,
		"encoding/base64": true, "encoding/hex": true,
		"crypto/rand": true, "crypto": true,
		"go/ast": true, "go/parser": true, "go/token": true,
		"go/format": true, "go/types": true, "go/doc": true,
		"go/printer": true, "go/scanner": true,
		"go/constant": true, "go/importer": true, "go/build": true,
		"gopkg.in/yaml.v3": true,
	}
	if stdlibs[path] {
		return true
	}
	if strings.Contains(path, "golang.org/x/") {
		return true
	}
	if strings.Contains(path, "google.golang.org/") {
		return true
	}
	if strings.HasPrefix(path, "github.com/") && strings.Count(path, "/") >= 2 {
		return false
	}
	return false
}
