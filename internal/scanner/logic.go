package scanner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
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
		case "typescript", "javascript":
			findings = append(findings, d.detectJavaScript(file.Content, file.Path)...)
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

func (d *LogicDetector) checkLoopBounds(n *ast.ForStmt, fset *token.FileSet) []types.Finding {
	var findings []types.Finding

	if n.Cond == nil {
		return nil
	}

	bin, ok := n.Cond.(*ast.BinaryExpr)
	if !ok {
		return nil
	}

	pos := fset.Position(n.Pos())

	if bin.Op.String() == "<=" {
		if _, ok := bin.X.(*ast.Ident); !ok {
			return nil
		}

		lit, ok := bin.Y.(*ast.BasicLit)
		if !ok {
			return nil
		}

		if lit.Value == "len(x)" || lit.Value == "len(xs)" {
			return nil
		}

		findings = append(findings, types.Finding{
			Rule:       "off-by-one",
			Severity:   types.SeverityWarning,
			Message:    fmt.Sprintf("Loop uses <= with %s — likely off-by-one error", lit.Value),
			Line:       pos.Line,
			Suggestion: "Use < instead of <= to avoid iterating one past the intended bound",
			Category:   "",
		})
	}

	return findings
}

func (d *LogicDetector) checkInvertedConditional(n *ast.BinaryExpr, fset *token.FileSet) []types.Finding {
	var findings []types.Finding

	op := n.Op.String()

	suspicious := map[string]string{
		">":  "potential inverted conditional: > vs <",
		"<":  "potential inverted conditional: < vs >",
		">=": "potential inverted conditional: >= vs <=",
		"<=": "potential inverted conditional: <= vs >=",
	}

	msg, ok := suspicious[op]
	if !ok {
		return nil
	}

	if !isComparisonWithZero(n) {
		return nil
	}

	pos := fset.Position(n.Pos())
	findings = append(findings, types.Finding{
		Rule:       "inverted-conditional",
		Severity:   types.SeverityInfo,
		Message:    msg,
		Line:       pos.Line,
		Suggestion: "Verify the comparison direction is correct",
		Category:   "",
	})

	return findings
}

func isComparisonWithZero(n *ast.BinaryExpr) bool {
	if lit, ok := n.Y.(*ast.BasicLit); ok {
		return lit.Value == "0" || lit.Value == "-1"
	}
	if lit, ok := n.X.(*ast.BasicLit); ok {
		return lit.Value == "0" || lit.Value == "-1"
	}
	return false
}

func (d *LogicDetector) checkEmptyCheck(n *ast.IfStmt, fset *token.FileSet) []types.Finding {
	var findings []types.Finding

	bin, ok := n.Cond.(*ast.BinaryExpr)
	if !ok {
		return nil
	}

		if bin.Op.String() == "!=" {
			if _, ok := bin.X.(*ast.Ident); ok {
				if lit, ok := bin.Y.(*ast.BasicLit); ok && lit.Value == "0" {
					_ = lit
					return nil
				}
			}
		}

	if call, ok := bin.X.(*ast.CallExpr); ok {
		funcName := ""
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			funcName = sel.Sel.Name
		} else if ident, ok := call.Fun.(*ast.Ident); ok {
			funcName = ident.Name
		}

		if funcName == "len" && bin.Op.String() == ">" && !isComparisonWithZero(bin) {
			return nil
		}

		if funcName == "len" && bin.Op.String() == "==" {
			if lit, ok := bin.Y.(*ast.BasicLit); ok && lit.Value == "0" {
				_ = lit
				if !strings.Contains(fset.Position(n.Pos()).String(), "error") &&
					!strings.Contains(fset.Position(n.Pos()).String(), "err") {
					return nil
				}
			}
		}
	}

	return findings
}

func (d *LogicDetector) checkShadowedVariable(n *ast.AssignStmt, fset *token.FileSet) []types.Finding {
	var findings []types.Finding
	_ = fset

	if n.Tok.String() != ":=" {
		return nil
	}

	return findings
}

func (d *LogicDetector) checkSelfAssignment(n *ast.AssignStmt, fset *token.FileSet) []types.Finding {
	var findings []types.Finding

	if len(n.Lhs) != 1 || len(n.Rhs) != 1 {
		return nil
	}

	lhsIdent, ok := n.Lhs[0].(*ast.Ident)
	if !ok {
		return nil
	}

	rhsIdent, ok := n.Rhs[0].(*ast.Ident)
	if !ok {
		return nil
	}

	if lhsIdent.Name == rhsIdent.Name {
		pos := fset.Position(n.Pos())
		findings = append(findings, types.Finding{
			Rule:       "self-assignment",
			Severity:   types.SeverityWarning,
			Message:    fmt.Sprintf("Self-assignment: '%s = %s' — likely a bug", lhsIdent.Name, rhsIdent.Name),
			Line:       pos.Line,
			Suggestion: "This assigns a variable to itself — intended to be a different variable?",
			Category:   "",
		})
	}

	return findings
}

func (d *LogicDetector) checkMissingDefault(n *ast.SwitchStmt, fset *token.FileSet) []types.Finding {
	var findings []types.Finding

	if n.Tag == nil {
		return nil
	}

	hasDefault := false
	for _, stmt := range n.Body.List {
		if cas, ok := stmt.(*ast.CaseClause); ok && cas.List == nil {
			hasDefault = true
			break
		}
	}

	if !hasDefault {
		pos := fset.Position(n.Switch)
		findings = append(findings, types.Finding{
			Rule:       "missing-default",
			Severity:   types.SeverityInfo,
			Message:    "Switch statement without default case — unhandled values will be silently ignored",
			Line:       pos.Line,
			Suggestion: "Add a default case to handle unexpected values",
			Category:   "",
		})
	}

	return findings
}

func (d *LogicDetector) checkInfiniteLoops(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "for {" ) || strings.HasPrefix(trimmed, "for ;;") {
			hasBreak := false
			hasReturn := false
			for j := i + 1; j < len(lines) && j < i+30; j++ {
				nested := strings.TrimSpace(lines[j])
				if strings.HasPrefix(nested, "break") || strings.HasPrefix(nested, "return") {
					hasBreak = true
					hasReturn = true
					break
				}
				if nested == "}" {
					break
				}
			}
			if !hasBreak && !hasReturn {
				findings = append(findings, types.Finding{
					Rule:       "infinite-loop",
					Severity:   types.SeverityError,
					Message:    "Infinite loop detected — no break, return, or condition found within 30 lines",
					Line:       i + 1,
					Suggestion: "Add a break condition or return statement inside the loop",
					Category:   path,
				})
			}
		}
	}

	return findings
}

func (d *LogicDetector) checkEdgeCases(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	hasSliceParam := false
	hasNilCheck := false
	hasMapParam := false
	hasMapNilCheck := false
	hasChanParam := false
	hasChanCloseCheck := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		slicePattern := regexp.MustCompile(`\[\](\w+)`)
		mapPattern := regexp.MustCompile(`map\[`)
		chanPattern := regexp.MustCompile(`chan `)

		if slicePattern.MatchString(trimmed) {
			hasSliceParam = true
		}
		if mapPattern.MatchString(trimmed) {
			hasMapParam = true
		}
		if chanPattern.MatchString(trimmed) {
			hasChanParam = true
		}
		if strings.Contains(trimmed, "nil") && (strings.Contains(trimmed, "==") || strings.Contains(trimmed, "!=")) {
			hasNilCheck = true
			hasMapNilCheck = true
		}
		if strings.Contains(trimmed, "close(") {
			hasChanCloseCheck = true
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if hasSliceParam && !hasNilCheck {
			if strings.Contains(trimmed, "len(") && strings.Contains(trimmed, ") == 0") {
				continue
			}
		}

		if hasMapParam && !hasMapNilCheck {
			if strings.Contains(trimmed, "make(") && strings.Contains(trimmed, "map") {
				continue
			}
		}

		if hasChanParam && !hasChanCloseCheck {
			if strings.Contains(trimmed, "defer close(") || strings.Contains(trimmed, "close(") {
				continue
			}
		}

		if strings.Contains(trimmed, ".Close(") && strings.HasPrefix(trimmed, "resp.") {
			if !strings.Contains(trimmed, "defer") {
				hasDefer := false
				for j := i - 5; j < i; j++ {
					if j >= 0 && strings.Contains(lines[j], "defer") && strings.Contains(lines[j], ".Close") {
						hasDefer = true
						break
					}
				}
				if !hasDefer {
					findings = append(findings, types.Finding{
						Rule:       "missing-defer-close",
						Severity:   types.SeverityWarning,
						Message:    "Resource .Close() called without defer — may leak under error paths",
						Line:       i + 1,
						Suggestion: "Use 'defer resource.Close()' immediately after creating the resource",
						Category:   path,
					})
				}
			}
		}
	}

	linesForVars := content
	varDecl := regexp.MustCompile(`var\s+(\w+)\s+(\w+)`)
	matches := varDecl.FindAllStringSubmatch(linesForVars, -1)
	for _, m := range matches {
		varName := m[1]
		varType := m[2]
		if strings.HasPrefix(varType, "[]") || strings.HasPrefix(varType, "map[") || strings.HasPrefix(varType, "chan ") {
			used := strings.Count(linesForVars, varName)
			if used <= 1 {
				findings = append(findings, types.Finding{
					Rule:       "unused-declaration",
					Severity:   types.SeverityInfo,
					Message:    fmt.Sprintf("Variable '%s' of type '%s' declared but only referenced once", varName, varType),
					Suggestion: "Check if this variable is needed, or if it's a leftover from refactoring",
					Category:   path,
				})
			}
		}
	}

	return findings
}

func (d *LogicDetector) checkMutableDefault(line string, lineNum int, path string) types.Finding {
	return types.Finding{}
}

func (d *LogicDetector) detectCommon(content, path string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if strings.Contains(trimmed, "<= 0") || strings.Contains(trimmed, "< 0") {
			findings = append(findings, types.Finding{
				Rule:       "inclusive-zero-check",
				Severity:   types.SeverityInfo,
				Message:    "Bound check includes 0 — may not be intentional",
				Line:       i + 1,
				Suggestion: "Verify that zero should be included in this comparison",
				Category:   path,
			})
		}

		commentCheck := strings.Count(trimmed, "/") >= 4
		codeCheck := strings.Count(trimmed, "//") == 0 && strings.Count(trimmed, "/*") == 0
		if commentCheck && codeCheck {
			if strings.Contains(trimmed, "if ") || strings.Contains(trimmed, "for ") || strings.Contains(trimmed, "return ") {
				continue
			}
		}
	}

	return findings
}
