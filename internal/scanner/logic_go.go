package scanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)
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

