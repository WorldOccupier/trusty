package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/WorldOccupier/trusty/internal/config"
)

type Result struct {
	Passed  bool
	Checks  []CheckResult
	Message string
}

type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

func Run(cfgPath string) *Result {
	res := &Result{Passed: true}

	res.Checks = append(res.Checks, checkConfig(cfgPath))
	res.Checks = append(res.Checks, checkGitRepo())
	res.Checks = append(res.Checks, checkGitHooks())
	res.Checks = append(res.Checks, checkLLMKey(cfgPath))
	res.Checks = append(res.Checks, checkCacheFiles())
	res.Checks = append(res.Checks, checkGitignore())

	for _, c := range res.Checks {
		if !c.Passed {
			res.Passed = false
		}
	}

	if res.Passed {
		res.Message = "All checks passed"
	} else {
		var fails []string
		for _, c := range res.Checks {
			if !c.Passed {
				fails = append(fails, fmt.Sprintf("%s: %s", c.Name, c.Message))
			}
		}
		res.Message = fmt.Sprintf("%d check(s) failed:\n  %s", len(fails), strings.Join(fails, "\n  "))
	}

	return res
}

func checkConfig(path string) CheckResult {
	if path == "" {
		for _, name := range []string{".trusty.yml", ".trusty.yaml"} {
			if _, err := os.Stat(name); err == nil {
				path = name
				break
			}
		}
	}

	if path == "" {
		return CheckResult{
			Name:    "config",
			Passed:  true,
			Message: "No config file found, using defaults",
		}
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return CheckResult{
			Name:    "config",
			Passed:  false,
			Message: fmt.Sprintf("Cannot read config file: %v", err),
		}
	}

	cfg, err := config.Load(path)
	if err != nil {
		return CheckResult{
			Name:    "config",
			Passed:  false,
			Message: fmt.Sprintf("Invalid config: %v", err),
		}
	}

	if cfg.Version < 1 {
		return CheckResult{
			Name:    "config",
			Passed:  false,
			Message: fmt.Sprintf("Unsupported config version: %d", cfg.Version),
		}
	}

	_ = data
	return CheckResult{
		Name:    "config",
		Passed:  true,
		Message: fmt.Sprintf("Valid config (%s)", path),
	}
}

func checkGitRepo() CheckResult {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	if err := cmd.Run(); err != nil {
		return CheckResult{
			Name:    "git-repo",
			Passed:  false,
			Message: "Not a git repository",
		}
	}

	cmd = exec.Command("git", "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Name:    "git-repo",
			Passed:  true,
			Message: "Git repo exists but has no commits",
		}
	}

	hash := strings.TrimSpace(string(out))
	shortHash := hash
	if len(hash) > 8 {
		shortHash = hash[:8]
	}
	return CheckResult{
		Name:    "git-repo",
		Passed:  true,
		Message: fmt.Sprintf("Valid git repo at HEAD %s", shortHash),
	}
}

func checkLLMKey(cfgPath string) CheckResult {
	if cfgPath == "" {
		for _, name := range []string{".trusty.yml", ".trusty.yaml"} {
			if _, err := os.Stat(name); err == nil {
				cfgPath = name
				break
			}
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return CheckResult{
			Name:    "llm-key",
			Passed:  true,
			Message: "Cannot load config, skipping LLM check",
		}
	}

	if cfg.LLM.Provider == "" {
		return CheckResult{
			Name:    "llm-key",
			Passed:  true,
			Message: "No LLM provider configured",
		}
	}

	if cfg.LLM.APIKey == "" {
		return CheckResult{
			Name:    "llm-key",
			Passed:  false,
			Message: fmt.Sprintf("No API key for provider %q — set %s_API_KEY", cfg.LLM.Provider, strings.ToUpper(cfg.LLM.Provider)),
		}
	}

	keyPreview := cfg.LLM.APIKey
	if len(keyPreview) > 8 {
		keyPreview = keyPreview[:4] + "..." + keyPreview[len(keyPreview)-4:]
	}
	return CheckResult{
		Name:    "llm-key",
		Passed:  true,
		Message: fmt.Sprintf("API key configured for %s (%s)", cfg.LLM.Provider, keyPreview),
	}
}

func checkGitHooks() CheckResult {
	gitDir := ".git"
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return CheckResult{Name: "git-hooks", Passed: true, Message: "Not a git repository"}
	}
	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		return CheckResult{Name: "git-hooks", Passed: true, Message: "No pre-commit hook installed (run: trusty install-hook)"}
	}
	data, _ := os.ReadFile(hookPath)
	if strings.Contains(string(data), "trusty") {
		return CheckResult{Name: "git-hooks", Passed: true, Message: "Trusty pre-commit hook installed"}
	}
	return CheckResult{Name: "git-hooks", Passed: true, Message: "Pre-commit hook exists (not Trusty)"}
}

func checkGitignore() CheckResult {
	data, err := os.ReadFile(".gitignore")
	if os.IsNotExist(err) {
		return CheckResult{Name: "gitignore", Passed: true, Message: "No .gitignore file (recommended for cache files)"}
	}
	if err != nil {
		return CheckResult{Name: "gitignore", Passed: false, Message: fmt.Sprintf("Cannot read .gitignore: %v", err)}
	}
	content := string(data)
	missing := []string{}
	for _, entry := range []string{".trusty-cache.json", ".trusty-history.json", ".trusty-audit.jsonl"} {
		if !strings.Contains(content, entry) {
			missing = append(missing, entry)
		}
	}
	if len(missing) > 0 {
		return CheckResult{Name: "gitignore", Passed: true, Message: fmt.Sprintf("Add to .gitignore: %s", strings.Join(missing, ", "))}
	}
	return CheckResult{Name: "gitignore", Passed: true, Message: "Trusty cache files are gitignored"}
}

func checkCacheFiles() CheckResult {
	var issues []string

	cacheFiles := []string{".trusty-cache.json", ".trusty-history.json", ".trusty-audit.jsonl"}
	for _, name := range cacheFiles {
		if _, err := os.Stat(name); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			issues = append(issues, fmt.Sprintf("%s: cannot read", name))
			continue
		}

		if strings.HasSuffix(name, ".json") {
			if !json.Valid(data) {
				issues = append(issues, fmt.Sprintf("%s: invalid JSON", name))
			}
		}
	}

	if len(issues) > 0 {
		return CheckResult{
			Name:    "cache-files",
			Passed:  false,
			Message: strings.Join(issues, "; "),
		}
	}

	return CheckResult{
		Name:    "cache-files",
		Passed:  true,
		Message: "Cache files OK",
	}
}
