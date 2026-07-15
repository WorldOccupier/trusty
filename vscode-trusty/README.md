# Trusty VS Code Extension

Inline diagnostics and scan results from Trusty AI Code Verification CLI.

## Features

- **Scan current file**: Run `Trusty: Scan Current File` to check the active file for AI-generated code issues
- **Scan all changed files**: Run `Trusty: Scan All Changed Files` for a full workspace scan
- **Inline diagnostics**: See issues highlighted directly in the editor with severity coloring

## Requirements

- [Trusty CLI](https://github.com/WorldOccupier/trusty) installed and available in PATH
- Go, Python, or JavaScript/TypeScript project

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `trusty.minScore` | `70` | Minimum trust score threshold |
| `trusty.cliPath` | `trusty` | Path to trusty CLI binary |
