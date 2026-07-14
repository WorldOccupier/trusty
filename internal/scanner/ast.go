package scanner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

type DeepASTAnalyzer struct{}

func NewDeepASTAnalyzer() *DeepASTAnalyzer {
	return &DeepASTAnalyzer{}
}

func (a *DeepASTAnalyzer) Analyze(path string, content string) []types.Finding {
	if !strings.HasSuffix(path, ".go") {
		return nil
	}

	var findings []types.Finding

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, content, parser.AllErrors)
	if err != nil {
		return nil
	}

	findings = append(findings, a.checkNilDereferences(f, fset)...)
	findings = append(findings, a.checkErrorHandling(f, fset)...)
	findings = append(findings, a.checkNilInterface(f, fset)...)
	findings = append(findings, a.checkCloseDeferred(f, fset)...)
	findings = append(findings, a.checkSliceBounds(f, fset)...)

	return findings
}

func (a *DeepASTAnalyzer) checkNilDereferences(f *ast.File, fset *token.FileSet) []types.Finding {
	var findings []types.Finding

	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		if ident.Name == "nil" {
			pos := fset.Position(sel.Pos())
			findings = append(findings, types.Finding{
				Rule:       "nil-dereference",
				Severity:   types.SeverityError,
				Message:    "Potential nil dereference on " + sel.Sel.Name,
				Line:       pos.Line,
				Column:     pos.Column,
				Category:   "ast-analysis",
				Suggestion: "Add nil check before accessing " + ident.Name + "." + sel.Sel.Name,
			})
		}
		return true
	})

	return findings
}

func (a *DeepASTAnalyzer) checkErrorHandling(f *ast.File, fset *token.FileSet) []types.Finding {
	var findings []types.Finding
	funcs := map[string]bool{
		"Write": true, "Read": true, "Close": true,
		"Flush": true, "Sync": true, "Exec": true,
		"Run": true, "Do": true,
	}

	callIsStandalone := map[ast.Node]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		expr, ok := n.(*ast.ExprStmt)
		if !ok {
			return true
		}
		if call, ok := expr.X.(*ast.CallExpr); ok {
			callIsStandalone[call] = true
		}
		return true
	})

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if !funcs[sel.Sel.Name] {
			return true
		}

		if !callIsStandalone[call] {
			return true
		}

		pos := fset.Position(call.Pos())

		findings = append(findings, types.Finding{
			Rule:       "unchecked-error",
			Severity:   types.SeverityWarning,
			Message:    fmt.Sprintf("Unchecked error from %s.%s()", typeOf(sel.X), sel.Sel.Name),
			Line:       pos.Line,
			Category:   "ast-analysis",
			Suggestion: "Check and handle the error: if err := " + typeOf(sel.X) + "." + sel.Sel.Name + "(); err != nil { ... }",
		})
		return true
	})

	return findings
}

func (a *DeepASTAnalyzer) checkNilInterface(f *ast.File, fset *token.FileSet) []types.Finding {
	var findings []types.Finding

	ast.Inspect(f, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}

		for _, expr := range ret.Results {
			ident, ok := expr.(*ast.Ident)
			if !ok || ident.Name != "nil" {
				continue
			}

			funcDecl := enclosingFunc(ret, f)
			if funcDecl == nil {
				continue
			}

			if funcDecl.Type.Results != nil && len(funcDecl.Type.Results.List) > 0 {
				retType := funcDecl.Type.Results.List[0].Type
				if _, isInterface := retType.(*ast.InterfaceType); isInterface {
					findings = append(findings, types.Finding{
						Rule:       "typed-nil-interface",
						Severity:   types.SeverityWarning,
						Message:    fmt.Sprintf("Returning nil as %s — callers checking == nil will miss this", typeOf(retType)),
						Line:       fset.Position(ident.Pos()).Line,
						Category:   "ast-analysis",
						Suggestion: "Return a typed nil or concrete nil pointer instead",
					})
				}
			}
		}
		return true
	})

	return findings
}

func (a *DeepASTAnalyzer) checkCloseDeferred(f *ast.File, fset *token.FileSet) []types.Finding {
	var findings []types.Finding
	closables := map[string]bool{
		"os.Open": true, "os.Create": true, "net.Dial": true,
		"http.Get": true, "os.OpenFile": true,
	}

	ast.Inspect(f, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}

		callStr := exprString(call.Fun)
		if !closables[callStr] {
			return true
		}

		funcDecl := enclosingFunc(assign, f)
		if funcDecl == nil {
			return true
		}

		hasDeferredClose := false
		ast.Inspect(funcDecl, func(n2 ast.Node) bool {
			if deferStmt, ok := n2.(*ast.DeferStmt); ok {
				deferCall, ok := deferStmt.Call.Fun.(*ast.SelectorExpr)
				if ok && deferCall.Sel.Name == "Close" {
					hasDeferredClose = true
					return false
				}
			}
			return true
		})

		if !hasDeferredClose {
			pos := fset.Position(assign.Pos())
			for _, lhs := range assign.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if ok && ident.Name != "_" && ident.Name != "err" {
					findings = append(findings, types.Finding{
						Rule:       "missing-deferred-close",
						Severity:   types.SeverityWarning,
						Message:    fmt.Sprintf("%s not closed via defer", ident.Name),
						Line:       pos.Line,
						Category:   "ast-analysis",
						Suggestion: fmt.Sprintf("Add: defer %s.Close()", ident.Name),
					})
					break
				}
			}
		}
		return true
	})

	return findings
}

func (a *DeepASTAnalyzer) checkSliceBounds(f *ast.File, fset *token.FileSet) []types.Finding {
	var findings []types.Finding

	ast.Inspect(f, func(n ast.Node) bool {
		idx, ok := n.(*ast.IndexExpr)
		if !ok {
			return true
		}

		if _, ok := idx.X.(*ast.Ident); !ok {
			return true
		}

		lit, ok := idx.Index.(*ast.BasicLit)
		if !ok || lit.Kind != token.INT {
			return true
		}

		pos := fset.Position(idx.Pos())
		findings = append(findings, types.Finding{
			Rule:       "hardcoded-index",
			Severity:   types.SeverityInfo,
			Message:    fmt.Sprintf("Hardcoded index access %s[%s] — may panic if slice is too short", exprString(idx.X), lit.Value),
			Line:       pos.Line,
			Column:     pos.Column,
			Category:   "ast-analysis",
			Suggestion: "Check slice length before accessing or use range loop",
		})
		return true
	})

	return findings
}

func enclosingFunc(n ast.Node, f *ast.File) *ast.FuncDecl {
	var funcDecl *ast.FuncDecl
	ast.Inspect(f, func(n2 ast.Node) bool {
		if fd, ok := n2.(*ast.FuncDecl); ok {
			if fd.Pos() <= n.Pos() && n.End() <= fd.End() {
				funcDecl = fd
				return false
			}
		}
		return true
	})
	return funcDecl
}

func typeOf(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	default:
		return exprString(expr)
	}
}

func exprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	case *ast.CallExpr:
		return exprString(e.Fun) + "()"
	case *ast.ParenExpr:
		return "(" + exprString(e.X) + ")"
	case *ast.StarExpr:
		return "*" + exprString(e.X)
	case *ast.BasicLit:
		return e.Value
	case *ast.IndexExpr:
		return exprString(e.X) + "[" + exprString(e.Index) + "]"
	default:
		return fmt.Sprintf("%T", e)
	}
}
