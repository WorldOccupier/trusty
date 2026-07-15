# Trusty Roadmap

## Vision

Make Trusty the go-to AI code verification tool — the "go vet for AI-generated code."

## Completed

### Phase 1-7: Core Engine

All 30 CLI commands, 3-tier scan engine, 8k+ lines of Go, full CI/CD integrations.

### Refactoring & Docs

- Split `main.go` (1841 lines) into 7 files < 500 lines each
- Split `fingerprint.go` (584 lines) and `logic.go` (562 lines)
- Added Makefile with build timing, profiling, coverage
- Restructured docs into `docs/` with focused pages
- All `os.Exit(1)` calls refactored to error returns
- Full `go build ./... && go vet ./... && go test ./...` passes

## Next Up

### P0 — Adoption Barriers (quick wins, < 1 day each)

| Feature | Why | Effort |
|---------|-----|--------|
| `trusty demo` command | Lets anyone evaluate in 10 seconds without a real project | ~2 hours |
| GitHub Releases + cross-compile | Binary downloads instead of `go install`; GitHub Action is 10x faster | ~1 hour |
| Homebrew tap | `brew install trusty` — easiest macOS install path | ~30 min |
| Static analysis without API key | Basic checks work out of the box, zero config | ~30 min |
| VS Code extension publish | In-editor feedback, highest visibility channel | ~2 hours |
| GitHub Action install from release | 2s vs 30s setup time | ~15 min |

### P1 — Visibility & Growth (1-3 days each)

| Feature | Why |
|---------|-----|
| Hacker News launch post | Targeted at Go developers and AI engineering teams |
| Reddit r/golang Show & Tell | Technical audience that can immediately evaluate |
| GitHub App (not just Action) | Auto-installs on repos, comments on PRs without config |
| Online web playground | Paste code, see results — no install required |
| `trusty scan` performance benchmarks | Quantify "300ms vs 30s for ChatGPT" |

### P2 — Enterprise Ready (3-5 days each)

| Feature | Why |
|---------|-----|
| GitHub Marketplace listing | Discoverability for GitHub users |
| Homebrew core (not just tap) | Broader macOS reach |
| Automated security scanning of Trusty itself | Trust the trust tool |
| Contribution guide + issue templates | Community building |
| Plugin marketplace | Third-party scanner ecosystem |

## Key Metrics for POC Success

1. `brew install trusty && trusty demo` works in < 30 seconds
2. First scan on a real PR produces actionable findings
3. VS Code extension shows inline diagnostics
4. GitHub Action runs in < 10 seconds (not 30s+ go install)

## Outreach Targets

- **Individual devs**: VS Code marketplace, Homebrew, HN, Reddit
- **Engineering teams**: GitHub App, GitHub Actions, GitLab CI
- **Enterprise**: SSO, audit trail, policy-as-code, Helm chart
- **Partners**: Qodo, GitHub Copilot, GitLab Duo teams
- **Conferences**: GopherCon, KubeCon, AI Engineer Summit
