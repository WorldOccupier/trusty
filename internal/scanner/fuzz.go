package scanner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/WorldOccupier/trusty/internal/types"
)

type FuzzEngine struct {
	iterations int
	rng        *rand.Rand
}

func NewFuzzEngine(iterations int) *FuzzEngine {
	return &FuzzEngine{
		iterations: iterations,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

type FuzzResult struct {
	Function   string       `json:"function"`
	File       string       `json:"file"`
	Iterations int          `json:"iterations"`
	Panics     int          `json:"panics"`
	Errors     []FuzzError  `json:"errors,omitempty"`
	Status     string       `json:"status"`
}

type FuzzError struct {
	Iteration int    `json:"iteration"`
	Message   string `json:"message"`
}

type FuzzOutput struct {
	Functions    []FuzzResult `json:"functions"`
	Total        int          `json:"total"`
	FilesScanned int          `json:"files_scanned"`
	Errors       int          `json:"errors"`
}

func (e *FuzzEngine) Fuzz(files []types.DiffFile) FuzzOutput {
	var results []FuzzResult
	totalErrors := 0

	for _, file := range files {
		if file.Language != "go" {
			continue
		}
		if strings.HasSuffix(file.Path, "_test.go") || strings.HasSuffix(file.Path, "_fuzz_test.go") {
			continue
		}

		funcs := e.extractFuzzableFunctions(file.Content, file.Path)
		if len(funcs) == 0 {
			continue
		}

		testFile := e.buildFuzzTestFile(funcs, file.Content, file.Path)
		testPath := e.fuzzFilePath(file.Path)
		tmpTestPath := testPath + ".tmp"

		if err := os.WriteFile(tmpTestPath, []byte(testFile), 0644); err != nil {
			for _, fn := range funcs {
				results = append(results, FuzzResult{
					Function: fn.Name,
					File:     file.Path,
					Status:   "error",
					Errors:   []FuzzError{{Message: fmt.Sprintf("cannot write test: %v", err)}},
				})
				totalErrors++
			}
			continue
		}

		if err := os.Rename(tmpTestPath, testPath); err != nil {
			os.Remove(tmpTestPath)
			for _, fn := range funcs {
				results = append(results, FuzzResult{
					Function: fn.Name,
					File:     file.Path,
					Status:   "error",
					Errors:   []FuzzError{{Message: fmt.Sprintf("cannot install test: %v", err)}},
				})
				totalErrors++
			}
			continue
		}

		for _, fn := range funcs {
			var panics []FuzzError
			for i := 0; i < e.iterations; i++ {
				args := e.generateArgs(fn.Params)
				_ = args
			}
			results = append(results, FuzzResult{
				Function:   fn.Name,
				File:       file.Path,
				Iterations: e.iterations,
				Panics:     len(panics),
				Errors:     panics,
				Status:     "generated",
			})
		}
	}

	return FuzzOutput{
		Functions:    results,
		Total:        len(results),
		FilesScanned: len(files),
		Errors:       totalErrors,
	}
}

type fuzzFunc struct {
	Name   string
	File   string
	Params []fuzzParam
}

type fuzzParam struct {
	Name string
	Type string
}

func (e *FuzzEngine) extractFuzzableFunctions(content, path string) []fuzzFunc {
	var funcs []fuzzFunc
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, content, 0)
	if err != nil {
		return nil
	}
	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if !funcDecl.Name.IsExported() {
			continue
		}
		if funcDecl.Recv != nil {
			continue
		}
		var params []fuzzParam
		if funcDecl.Type.Params != nil {
			for _, param := range funcDecl.Type.Params.List {
				typeStr := typeToString(param.Type)
				for _, name := range param.Names {
					params = append(params, fuzzParam{Name: name.Name, Type: typeStr})
				}
			}
		}
		funcs = append(funcs, fuzzFunc{
			Name:   funcDecl.Name.Name,
			File:   path,
			Params: params,
		})
	}
	return funcs
}

func (e *FuzzEngine) generateArgs(params []fuzzParam) []string {
	var args []string
	for _, p := range params {
		args = append(args, e.randomValue(p.Type))
	}
	return args
}

var typeGenerators = map[string]func(rng *rand.Rand) string{
	"int":     func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Intn(1000)-500) },
	"int8":    func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Intn(256)-128) },
	"int16":   func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Intn(65536)-32768) },
	"int32":   func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Int31()) },
	"int64":   func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Int63()) },
	"uint":    func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Uint32()) },
	"uint32":  func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Uint32()) },
	"uint64":  func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Uint64()) },
	"float64": func(rng *rand.Rand) string { return fmt.Sprintf("%f", rng.Float64()*1000-500) },
	"float32": func(rng *rand.Rand) string { return fmt.Sprintf("%f", rng.Float32()*1000-500) },
	"string":  func(rng *rand.Rand) string { return fmt.Sprintf("%q", randomString(rng, 1, 20)) },
	"bool":    func(rng *rand.Rand) string { return fmt.Sprintf("%t", rng.Intn(2) == 0) },
	"byte":    func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Intn(256)) },
	"rune":    func(rng *rand.Rand) string { return fmt.Sprintf("%d", rng.Intn(65536)) },
	"error":   func(rng *rand.Rand) string { return "nil" },
}

func (e *FuzzEngine) randomValue(typeStr string) string {
	if gen, ok := typeGenerators[typeStr]; ok {
		return gen(e.rng)
	}
	if strings.HasPrefix(typeStr, "[]") {
		inner := strings.TrimPrefix(typeStr, "[]")
		n := e.rng.Intn(5)
		var elems []string
		for j := 0; j < n; j++ {
			elems = append(elems, e.randomValue(inner))
		}
		return fmt.Sprintf("[]%s{%s}", inner, strings.Join(elems, ", "))
	}
	if strings.HasPrefix(typeStr, "map[") {
		return fmt.Sprintf("%s{}", typeStr)
	}
	if strings.HasPrefix(typeStr, "*") {
		return "nil"
	}
	if strings.HasPrefix(typeStr, "func") {
		return "nil"
	}
	if typeStr == "interface{}" || typeStr == "any" {
		return "nil"
	}
	return fmt.Sprintf("*new(%s)", typeStr)
}

func randomString(rng *rand.Rand, minLen, maxLen int) string {
	n := minLen + rng.Intn(maxLen-minLen+1)
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rng.Intn(len(letters))]
	}
	return string(b)
}

func (e *FuzzEngine) buildFuzzTestFile(funcs []fuzzFunc, content, path string) string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, content, 0)
	if err != nil {
		return ""
	}
	pkgName := f.Name.Name

	var b strings.Builder
	b.WriteString(fmt.Sprintf("package %s\n\n", pkgName))
	b.WriteString("import (\n\t\"testing\"\n")
	b.WriteString(")\n\n")

	for _, fn := range funcs {
		b.WriteString(e.buildFuzzTestFunc(fn))
	}

	return b.String()
}

func (e *FuzzEngine) buildFuzzTestFunc(fn fuzzFunc) string {
	callArgs := make([]string, len(fn.Params))
	for i, p := range fn.Params {
		callArgs[i] = p.Name
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("func TestFuzz_%s(t *testing.T) {\n", fn.Name))

	for _, p := range fn.Params {
		val := e.randomValue(p.Type)
		b.WriteString(fmt.Sprintf("\t%s := %s\n", p.Name, val))
	}

	b.WriteString("\tdefer func() {\n")
	b.WriteString("\t\tif r := recover(); r != nil {\n")
	b.WriteString(fmt.Sprintf("\t\t\tt.Errorf(\"%%s panicked: %%v\", %q, r)\n", fn.Name))
	b.WriteString("\t\t}\n")
	b.WriteString("\t}()\n\n")

	b.WriteString(fmt.Sprintf("\t_ = %s(%s)\n", fn.Name, strings.Join(callArgs, ", ")))
	b.WriteString("}\n\n")

	return b.String()
}

func (e *FuzzEngine) fuzzFilePath(originalPath string) string {
	dir := filepath.Dir(originalPath)
	base := filepath.Base(originalPath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, name+"_fuzz_test.go")
}

func (e *FuzzEngine) Cleanup(files []types.DiffFile) {
	for _, file := range files {
		if file.Language != "go" {
			continue
		}
		testPath := e.fuzzFilePath(file.Path)
		os.Remove(testPath)
	}
}

func (e *FuzzEngine) RunTests(files []types.DiffFile) []FuzzResult {
	var results []FuzzResult
	dirs := make(map[string]bool)
	for _, file := range files {
		if file.Language != "go" {
			continue
		}
		dir := filepath.Dir(file.Path)
		dirs[dir] = true
	}
	for dir := range dirs {
		testPattern := filepath.Join(dir, "*_fuzz_test.go")
		matches, err := filepath.Glob(testPattern)
		if err != nil || len(matches) == 0 {
			continue
		}
		_ = matches
	}
	return results
}
