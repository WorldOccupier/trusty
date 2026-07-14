package scanner

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

type TestGenerator struct{}

func NewTestGenerator() *TestGenerator {
	return &TestGenerator{}
}

type ContractInfo struct {
	Package    string
	FuncName   string
	Params     []ParamInfo
	Returns    []ReturnInfo
	IsMethod   bool
	Receiver   string
	SourceFile string
}

type ParamInfo struct {
	Name string
	Type string
}

type ReturnInfo struct {
	Type string
}

func (g *TestGenerator) GenerateTests(files []types.DiffFile) ([]types.Finding, error) {
	var findings []types.Finding

	for _, file := range files {
		if file.Language != "go" {
			continue
		}

		if strings.HasSuffix(file.Path, "_test.go") {
			continue
		}

		contracts := g.extractContracts(file.Content, file.Path)
		if len(contracts) == 0 {
			continue
		}

		testFile, err := g.buildTestFile(contracts, file.Path)
		if err != nil {
			continue
		}

		testPath := g.testFilePath(file.Path)
		outDir := filepath.Dir(testPath)

		if err := os.MkdirAll(outDir, 0755); err != nil {
			findings = append(findings, types.Finding{
				Rule:       "testgen-output-error",
				Severity:   types.SeverityInfo,
				Message:    fmt.Sprintf("Could not create test directory for %s", file.Path),
				Category:   file.Path,
			})
			continue
		}

		if err := os.WriteFile(testPath, []byte(testFile), 0644); err != nil {
			findings = append(findings, types.Finding{
				Rule:       "testgen-output-error",
				Severity:   types.SeverityInfo,
				Message:    fmt.Sprintf("Could not write test file for %s", file.Path),
				Category:   file.Path,
			})
			continue
		}

		findings = append(findings, types.Finding{
			Rule:       "test-generated",
			Severity:   types.SeverityInfo,
			Message:    fmt.Sprintf("Generated behavioral tests for %d function(s) in %s", len(contracts), filepath.Base(file.Path)),
			Suggestion: fmt.Sprintf("Tests written to %s", testPath),
			Category:   file.Path,
		})
	}

	return findings, nil
}

func (g *TestGenerator) extractContracts(content, path string) []ContractInfo {
	var contracts []ContractInfo

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, content, 0)
	if err != nil {
		return nil
	}

	packageName := f.Name.Name

	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}

		if !funcDecl.Name.IsExported() {
			continue
		}

		if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
			continue
		}

		contract := ContractInfo{
			Package:    packageName,
			FuncName:   funcDecl.Name.Name,
			SourceFile: path,
			IsMethod:   funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0,
		}

		if contract.IsMethod {
			recvType := funcDecl.Recv.List[0].Type
			switch t := recvType.(type) {
			case *ast.Ident:
				contract.Receiver = t.Name
			case *ast.StarExpr:
				if ident, ok := t.X.(*ast.Ident); ok {
					contract.Receiver = "*" + ident.Name
				}
			}
		}

		for _, param := range funcDecl.Type.Params.List {
			for _, name := range param.Names {
				contract.Params = append(contract.Params, ParamInfo{
					Name: name.Name,
					Type: typeToString(param.Type),
				})
			}
		}

		if funcDecl.Type.Results != nil {
			for _, result := range funcDecl.Type.Results.List {
				rt := typeToString(result.Type)
				contract.Returns = append(contract.Returns, ReturnInfo{Type: rt})
			}
		}

		contracts = append(contracts, contract)
	}

	return contracts
}

func (g *TestGenerator) buildTestFile(contracts []ContractInfo, sourcePath string) (string, error) {
	var b strings.Builder

	packageName := contracts[0].Package

	b.WriteString(fmt.Sprintf("package %s\n\n", packageName))
	b.WriteString("import (\n\t\"testing\"\n)\n\n")

	for _, c := range contracts {
		g.writeTestCase(&b, c)
	}

	out, err := format.Source([]byte(b.String()))
	if err != nil {
		return b.String(), fmt.Errorf("formatting test file: %w", err)
	}

	return string(out), nil
}

func (g *TestGenerator) writeTestCase(b *strings.Builder, c ContractInfo) {
	testName := fmt.Sprintf("Test%s_Contract", c.FuncName)

	b.WriteString(fmt.Sprintf("func %s(t *testing.T) {\n", testName))

	if len(c.Params) > 0 {
		b.WriteString("\t// Arrange\n")
		for _, p := range c.Params {
			b.WriteString(fmt.Sprintf("\tvar %s %s\n", p.Name, p.Type))
		}
	}

	returnCount := len(c.Returns)
	if returnCount > 0 {
		returnDecl := "\n\t// Act\n\t"
		if returnCount == 1 {
			returnDecl += fmt.Sprintf("result := %s(", c.FuncName)
		} else if returnCount == 2 {
			returnDecl += fmt.Sprintf("result, err := %s(", c.FuncName)
		} else {
			returnDecl += fmt.Sprintf("result, _, err := %s(", c.FuncName)
		}
		b.WriteString(returnDecl)
	} else {
		b.WriteString(fmt.Sprintf("\n\t// Act\n\t%s(", c.FuncName))
	}

	for i, p := range c.Params {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(p.Name)
	}
	b.WriteString(")\n")

	if returnCount > 0 {
		b.WriteString("\n\t// Assert\n")

		for _, r := range c.Returns {
			if r.Type == "error" {
				b.WriteString("\tif err != nil {\n")
				b.WriteString(fmt.Sprintf("\t\tt.Errorf(\"%%s returned error: %%v\", \"%s\", err)\n", c.FuncName))
				b.WriteString("\t}\n")
			}
		}

		b.WriteString("\tif result == nil {\n")
		b.WriteString(fmt.Sprintf("\t\tt.Errorf(\"%%s returned nil result\", \"%s\")\n", c.FuncName))
		b.WriteString("\t}\n")
	}

	b.WriteString("}\n\n")
}

func (g *TestGenerator) testFilePath(originalPath string) string {
	dir := filepath.Dir(originalPath)
	base := filepath.Base(originalPath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, name+"_trusty_test.go")
}

func typeToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + typeToString(t.X)
	case *ast.SelectorExpr:
		return typeToString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeToString(t.Elt)
		}
		return fmt.Sprintf("[%s]%s", t.Len, typeToString(t.Elt))
	case *ast.MapType:
		return fmt.Sprintf("map[%s]%s", typeToString(t.Key), typeToString(t.Value))
	case *ast.ChanType:
		return "chan " + typeToString(t.Value)
	case *ast.FuncType:
		return "func(...)"
	case *ast.InterfaceType:
		return "interface{}"
	default:
		return fmt.Sprintf("%T", expr)
	}
}

func FormatTestFile(src string) string {
	formatted, err := format.Source([]byte(src))
	if err != nil {
		return src
	}
	return string(formatted)
}
