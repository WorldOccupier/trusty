package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

type LogicDetector struct{}

func NewLogicDetector() *LogicDetector {
	return &LogicDetector{}
}

func (d *LogicDetector) Detect(files []types.DiffFile) []types.Finding {
	var findings []types.Finding

	for _, file := range files {
		switch file.Language {
		case "go":
			findings = append(findings, d.detectGo(file.Content, file.Path)...)
		case "python":
			findings = append(findings, d.detectPython(file.Content, file.Path)...)
			findings = append(findings, d.detectPythonDeep(file.Content, file.Path)...)
		case "typescript", "javascript":
			findings = append(findings, d.detectJavaScript(file.Content, file.Path)...)
			findings = append(findings, d.detectJavaScriptDeep(file.Content, file.Path)...)
		case "java":
			findings = append(findings, d.detectJava(file.Content, file.Path)...)
			findings = append(findings, d.checkJavaInfiniteLoops(file.Content, file.Path)...)
		case "rust":
			findings = append(findings, d.detectRust(file.Content, file.Path)...)
		}
		for i := range findings {
			if findings[i].Category == "" {
				findings[i].Category = file.Path
			}
		}
	}

	return findings
}

func (d *LogicDetector) detectGo(content, path string) []types.Finding {
	var findings []types.Finding

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, content, parser.AllErrors)
	if err != nil {
		return nil
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ForStmt:
			findings = append(findings, d.checkLoopBounds(x, fset)...)
		case *ast.BinaryExpr:
			findings = append(findings, d.checkInvertedConditional(x, fset)...)
		case *ast.IfStmt:
			findings = append(findings, d.checkEmptyCheck(x, fset)...)
		case *ast.AssignStmt:
			findings = append(findings, d.checkShadowedVariable(x, fset)...)
			findings = append(findings, d.checkSelfAssignment(x, fset)...)
		case *ast.SwitchStmt:
			findings = append(findings, d.checkMissingDefault(x, fset)...)
		}
		return true
	})

	findings = append(findings, d.checkInfiniteLoops(content, path)...)
	findings = append(findings, d.checkEdgeCases(content, path)...)

	return findings
}

func (d *LogicDetector) detectPython(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.Contains(trimmed, "==") && strings.Contains(trimmed, "True") {
			if strings.Contains(trimmed, "if ") || strings.Contains(trimmed, "elif ") {
				findings = append(findings, types.Finding{
					Rule:       "redundant-equality",
					Severity:   types.SeverityInfo,
					Message:    "Redundant equality check: use 'if x:' instead of 'if x == True:'",
					Line:       i + 1,
					Suggestion: "Remove '== True' — it's redundant in a boolean context",
					Category:   path,
				})
			}
		}

		if strings.Contains(trimmed, "except:") {
			findings = append(findings, types.Finding{
				Rule:       "bare-except",
				Severity:   types.SeverityWarning,
				Message:    "Bare except clause catches all exceptions, including KeyboardInterrupt and SystemExit",
				Line:       i + 1,
				Suggestion: "Catch specific exception types instead of using bare except:",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "range(len(") {
			findings = append(findings, types.Finding{
				Rule:       "range-len-pattern",
				Severity:   types.SeverityWarning,
				Message:    "Use 'for i, item in enumerate(x)' instead of 'for i in range(len(x))'",
				Line:       i + 1,
				Suggestion: "Replace with 'for i, item in enumerate(x):'",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "is") && strings.Contains(trimmed, "None") && strings.Contains(trimmed, "==") {
			continue
		}
		if strings.Contains(trimmed, "== None") || strings.Contains(trimmed, "!= None") {
			findings = append(findings, types.Finding{
				Rule:       "none-comparison",
				Severity:   types.SeverityInfo,
				Message:    "Use 'is None' / 'is not None' instead of '== None' / '!= None'",
				Line:       i + 1,
				Suggestion: "Replace with 'is None' or 'is not None'",
				Category:   path,
			})
		}

		if strings.Contains(trimmed, "defaultdict") && strings.Contains(trimmed, "lambda") {
			if f := d.checkMutableDefault(trimmed, i+1, path); f.Severity != 0 {
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (d *LogicDetector) detectJavaScript(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		if strings.Contains(trimmed, "== ") || strings.Contains(trimmed, " ==") {
			if !strings.Contains(trimmed, "===") && !strings.Contains(trimmed, "!==") {
				if strings.Contains(trimmed, "if ") || strings.Contains(trimmed, "while ") || strings.Contains(trimmed, "return ") {
					findings = append(findings, types.Finding{
						Rule:       "loose-equality",
						Severity:   types.SeverityWarning,
						Message:    "Use === instead of == to avoid type coercion bugs",
						Line:       i + 1,
						Suggestion: "Replace == with === (or != with !==)",
						Category:   path,
					})
				}
			}
		}

		if strings.Contains(trimmed, "var ") {
			findings = append(findings, types.Finding{
				Rule:       "var-usage",
				Severity:   types.SeverityWarning,
				Message:    "Use 'const' or 'let' instead of 'var' to avoid hoisting bugs",
				Line:       i + 1,
				Suggestion: "Replace 'var' with 'const' or 'let'",
				Category:   path,
			})
		}
	}

	return findings
}

