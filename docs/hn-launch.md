# Hacker News Launch Post — Trusty

## Title Options

1. Trusty: Open-source CLI that verifies AI-generated code (41/100 trust score)
2. Show HN: Trusty — AI Code Verification CLI with 3-tier scanning engine  
3. AI-generated code has 1.7x more bugs — we built a tool to catch them

## Draft

[This would be posted as a text post on news.ycombinator.com]

---

AI coding assistants generate code that looks correct but contains subtle bugs,
hallucinated APIs, logic errors, and security vulnerabilities.

We built Trusty — an open-source CLI that automatically verifies AI-generated code.

**The problem:**
- AI-generated code has 1.7x more issues than human-written code (Stanford/MIT 2026)
- 1.75x more logic errors, 1.57x more security findings  
- 67% of devs spend extra time debugging AI code that's "almost right"
- 75% of tech leaders expect severe AI-code debt by 2027

**How Trusty works:**
- 3-tier engine: static analysis → LLM semantic analysis → behavioral verification
- Detects SQL injection, XSS, logic errors, hallucinated imports, and more
- Generates a trust score (0-100) per file
- Auto-fix suggestions for 16+ rule types

**Quick start:**
```bash
brew install trusty  # or go install
trusty demo          # 10-second demo with sample AI-code issues
trusty scan          # scan your staged changes
```

**What makes it different from existing linters:**
1. Purpose-built for AI-generated code patterns (self-assignment, hallucinated imports, shadowed variables, typed nil interfaces)
2. Trust score quantifies code quality on a 0-100 scale
3. Auto-fix suggestions reduce debugging time
4. CI/CD integration with GitHub Actions, GitLab CI, Jenkins, CircleCI
5. VS Code extension with auto-scan on save
6. Policy engine for team enforcement

**Stack:** Go, Cobra CLI, Bubble Tea TUI, ~25 internal packages

**Links:**
- GitHub: https://github.com/WorldOccupier/trusty
- Docs: https://github.com/WorldOccupier/trusty/tree/main/docs
- Homebrew: brew install trusty

Looking forward to your feedback!

---

## Launch Checklist

- [ ] Test `brew install trusty && trusty demo` end-to-end
- [ ] Verify GitHub Action badge is working
- [ ] Check all docs links
- [ ] Tagged v0.1.0 release
- [ ] Prepare to answer questions in comments
- [ ] Post at 9 AM ET for maximum visibility
