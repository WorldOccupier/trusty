# CI Integration

## GitHub Actions

The repository includes a composite action at `.github/actions/trusty/`.

```yaml
# .github/workflows/trusty.yml
name: Trusty Code Verification
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: ./.github/actions/trusty
        with:
          min-score: 70
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

The `ci` command auto-detects GitHub Actions from `GITHUB_ACTIONS` env var, runs scan, and posts a PR comment with findings.

## GitLab CI

The repository includes a `.gitlab-ci.yml` template.

```yaml
trusty-scan:
  stage: test
  script:
    - trusty ci
  only:
    - merge_requests
```

The `ci` command auto-detects GitLab CI from `GITLAB_CI` env var, runs scan, and posts an MR comment with findings.

## CI Auto-Detection

The `trusty ci` command detects the CI platform from environment variables:

| Platform | Env Var |
|----------|---------|
| GitHub Actions | `GITHUB_ACTIONS` |
| GitLab CI | `GITLAB_CI` |
| Jenkins | `JENKINS_URL` / `JENKINS_HOME` |
| CircleCI | `CIRCLECI` |

No configuration required. Runs scan and posts PR/MR comment on supported platforms.

## Exit Codes for CI Gating

All detection commands exit 1 when findings are present:

```bash
trusty scan --min-score 70 && echo "Clean" || echo "Issues found"
```

This enables native CI gating — pipeline steps can fail based on scan results.
