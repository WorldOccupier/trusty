package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/user/trustpilot/internal/types"
)

type StaticAnalyzer struct{}

func NewStaticAnalyzer() *StaticAnalyzer {
	return &StaticAnalyzer{}
}

func (s *StaticAnalyzer) Analyze(path, content string) []types.Finding {
	if path == "" && content == "" {
		return nil
	}

	lang := detectLanguage(path)
	switch lang {
	case "go":
		return s.analyzeGo(path, content)
	case "python":
		return s.analyzePython(content)
	case "typescript":
		return s.analyzeTypeScript(content)
	default:
		return nil
	}
}

func (s *StaticAnalyzer) analyzeGo(path, content string) []types.Finding {
	var findings []types.Finding

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, content, parser.AllErrors)
	if err != nil {
		return nil
	}

	imports := make(map[string]bool)
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		imports[path] = true
	}

	usedImports := make(map[string]bool)
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if ident, ok := x.X.(*ast.Ident); ok {
				usedImports[ident.Name] = true
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok {
					usedImports[ident.Name] = true
				}
			}
		}
		return true
	})

	firstImport := token.Position{}
	for impPath := range imports {
		parts := strings.Split(impPath, "/")
		name := parts[len(parts)-1]
		if !usedImports[name] && !isStdLib(impPath) {
			if firstImport.Line == 0 && len(f.Imports) > 0 {
				firstImport = fset.Position(f.Imports[0].Pos())
			}
			findings = append(findings, types.Finding{
				Rule:       "unused-import",
				Severity:   types.SeverityWarning,
				Message:    "Unused import: " + impPath,
				Line:       firstImport.Line,
				Column:     firstImport.Column,
				Suggestion: "Remove unused import: " + impPath,
				Category:   "static-analysis",
			})
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 {
				if call, ok := x.Rhs[0].(*ast.CallExpr); ok {
					if len(x.Lhs) == 1 {
						if id, ok := x.Lhs[0].(*ast.Ident); ok && id.Name == "_" {
							pos := fset.Position(call.Pos())
							findings = append(findings, types.Finding{
								Rule:       "unchecked-error",
								Severity:   types.SeverityError,
								Message:    "Error return value not checked",
								Line:       pos.Line,
								Column:     pos.Column,
								Suggestion: "Check the error return value",
								Category:   "static-analysis",
							})
						}
					}
				}
			}
		}
		return true
	})

	return findings
}

func (s *StaticAnalyzer) analyzePython(content string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, "import ") && strings.Contains(line, "*") {
			findings = append(findings, types.Finding{
				Rule:       "wildcard-import",
				Severity:   types.SeverityWarning,
				Message:    "Wildcard import makes it unclear which names are in scope",
				Line:       i + 1,
				Suggestion: "Use explicit imports instead of *",
				Category:   "static-analysis",
			})
		}
		if strings.Contains(line, "eval(") || strings.Contains(line, "exec(") {
			findings = append(findings, types.Finding{
				Rule:       "dangerous-function",
				Severity:   types.SeverityError,
				Message:    "Use of eval/exec can lead to code injection",
				Line:       i + 1,
				Suggestion: "Avoid eval()/exec() - use safer alternatives like ast.literal_eval()",
				Category:   "static-analysis",
			})
		}
	}
	return findings
}

func (s *StaticAnalyzer) analyzeTypeScript(content string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "any") && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "/*") {
			if strings.Contains(trimmed, ": any") || strings.Contains(trimmed, "as any") {
				findings = append(findings, types.Finding{
					Rule:       "any-type",
					Severity:   types.SeverityWarning,
					Message:    "Use of 'any' type disables type checking",
					Line:       i + 1,
					Suggestion: "Replace 'any' with a more specific type or 'unknown'",
					Category:   "static-analysis",
				})
			}
		}
	}
	return findings
}

func isStdLib(path string) bool {
	stdlibs := map[string]bool{
		"fmt": true, "os": true, "strings": true, "net": true,
		"net/http": true, "encoding/json": true, "io": true,
		"io/ioutil": true, "time": true, "context": true,
		"sync": true, "errors": true, "math": true, "sort": true,
		"strconv": true, "regexp": true, "path": true, "path/filepath": true,
		"bytes": true, "bufio": true, "log": true, "flag": true,
		"reflect": true, "crypto": true, "crypto/tls": true,
		"crypto/rand": true, "testing": true, "database/sql": true,
		"encoding/base64": true, "encoding/hex": true,
		"compress/gzip": true, "archive/tar": true, "archive/zip": true,
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
	return false
}
