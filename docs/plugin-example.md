# Plugin System Example

Trusty supports a Go plugin system. Plugins implement the `Checker` interface
and are loaded at runtime as `.so` files.

## Checker Interface

```go
type Checker interface {
    Name() string
    Check(file types.DiffFile) ([]types.Finding, error)
}
```

## Example Plugin: Todo Checker

Create `todo-checker/main.go`:

```go
package main

import (
    "strings"
    "github.com/WorldOccupier/trusty/internal/plugin"
    "github.com/WorldOccupier/trusty/internal/types"
)

type TodoChecker struct{}

func (t *TodoChecker) Name() string { return "todo-checker" }

func (t *TodoChecker) Check(file types.DiffFile) ([]types.Finding, error) {
    var findings []types.Finding
    lines := strings.Split(file.Content, "\n")
    for i, line := range lines {
        if strings.Contains(line, "TODO") || strings.Contains(line, "FIXME") {
            findings = append(findings, types.Finding{
                Rule:       "todo-found",
                Severity:   types.SeverityInfo,
                Message:    "TODO/FIXME comment found",
                Line:       i + 1,
                Category:   "plugin-todo",
                Suggestion: "Address the TODO before shipping",
            })
        }
    }
    return findings, nil
}

func NewChecker() plugin.Checker {
    return &TodoChecker{}
}
```

## Building and Using

```bash
go build -buildmode=plugin -o todo-checker.so ./todo-checker/
trusty scan --plugin ./todo-checker.so
```

## Notes

- Plugins must export a `NewChecker` function returning a `plugin.Checker`
- The plugin's `main` package is compiled with `-buildmode=plugin`
- Plugin `.so` files are loaded at runtime with `plugin.Open`
- The `types.DiffFile` struct provides `Path`, `Language`, `Diff`, and `Content` fields
