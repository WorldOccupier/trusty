# Contributing to Trusty

## Development Setup

1. Clone the repo
2. Run `go build ./...` to verify
3. Run `go test ./...` to test

## Code Style

- No comments in production code unless necessary
- All Go files must be under 500 lines
- Use `fmt.Errorf("context: %w", err)` for error wrapping
- Use `filepath.Clean()` on user-supplied paths
- Run `go vet ./...` before committing

## Pull Request Process

1. Create a feature branch
2. Make your changes
3. Add or update tests
4. Run `go build ./... && go vet ./... && go test ./...`
5. Submit a PR with a clear description

## Commit Messages

Use conventional commits format: `type(scope): description`

Examples:
- `feat(scanner): add Python AST analysis`
- `fix(security): handle nil pointer in config load`
- `docs: update README with new commands`

## Adding New Commands

1. Create a `handler_<name>.go` file in `cmd/trusty/`
2. Register via `init()` pattern in a separate file
3. Keep handlers under 500 lines
4. Add the command definition in a separate file

## Testing

- Write internal tests (`package foo`, not `package foo_test`)
- Use table-driven tests
- Create temp dirs with `t.TempDir()`
