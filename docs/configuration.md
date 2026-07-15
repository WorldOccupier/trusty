# Configuration

## `.trusty.yml`

```yaml
# .trusty.yml
version: 1

scan:
  tiers: [1, 2, 3]
  min_score: 70
  languages: [go, python, typescript]

llm:
  provider: openai        # openai, anthropic, ollama
  model: gpt-4o
  temperature: 0.1

rules:
  hallucination:
    severity: error
  logic_errors:
    severity: warning
  security:
    severity: error

output:
  format: json            # json, sarif, html
  ci_mode: false
```

## Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | int | `1` | Config schema version |
| `scan.tiers` | []int | `[1, 2, 3]` | Which tiers to run |
| `scan.min_score` | int | `70` | Minimum trust score threshold |
| `scan.languages` | []string | `[go, python, typescript]` | Languages to scan |
| `llm.provider` | string | `openai` | LLM provider (openai, anthropic, ollama) |
| `llm.model` | string | `gpt-4o` | Model name |
| `llm.temperature` | float | `0.1` | LLM temperature |
| `rules.hallucination.severity` | string | `error` | Hallucination detection severity |
| `rules.logic_errors.severity` | string | `warning` | Logic error severity |
| `rules.security.severity` | string | `error` | Security vulnerability severity |
| `output.format` | string | `json` | Default output format |
| `output.ci_mode` | bool | `false` | Enable CI-specific output |

## Policy Overlay

Team policies can be applied on top of local config:

```yaml
# team-policy.yml
min_score: 80
rules:
  security:
    severity: error
  hallucination:
    severity: error
```

Usage:
```bash
trusty scan --policy-file ./team-policy.yml
trusty scan --policy-url https://example.com/org-policy.yml
```
