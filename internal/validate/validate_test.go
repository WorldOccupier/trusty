package validate

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func gitInit(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v\n%s", err, out)
	}
}

func gitCommit(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = dir
	cmd.Run()
	cmd = exec.Command("git", "config", "user.name", "Test")
	cmd.Dir = dir
	cmd.Run()
	if err := os.WriteFile(filepath.Join(dir, "initial.txt"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	cmd.Run()
	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit failed: %v\n%s", err, out)
	}
}

func TestCheckConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	if err := os.WriteFile(path, []byte("version: 1\nscan:\n  min_score: 80\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkConfig(path)
	if !r.Passed {
		t.Errorf("expected passed, got: %s", r.Message)
	}
}

func TestCheckConfig_InvalidPath(t *testing.T) {
	r := checkConfig("/nonexistent/.trusty.yml")
	if r.Passed {
		t.Error("expected not passed for invalid path")
	}
	if r.Name != "config" {
		t.Errorf("Name = %q, want %q", r.Name, "config")
	}
}

func TestCheckConfig_MissingUsesDefaults(t *testing.T) {
	dir := chdirTemp(t)
	r := checkConfig("")
	if !r.Passed {
		t.Errorf("expected passed with defaults, got: %s", r.Message)
	}
	_ = dir
}

func TestCheckConfig_FindsFileInCWD(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, ".trusty.yml"), []byte("version: 1\nscan:\n  min_score: 90\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkConfig("")
	if !r.Passed {
		t.Errorf("expected passed, got: %s", r.Message)
	}
}

func TestCheckConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	if err := os.WriteFile(path, []byte(": : invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkConfig(path)
	if r.Passed {
		t.Error("expected not passed for invalid YAML")
	}
}

func TestCheckConfig_InvalidVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	if err := os.WriteFile(path, []byte("version: 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkConfig(path)
	if r.Passed {
		t.Error("expected not passed for version 0")
	}
}

func TestCheckConfig_FindsYamlExtension(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, ".trusty.yaml"), []byte("version: 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkConfig("")
	if !r.Passed {
		t.Errorf("expected passed, got: %s", r.Message)
	}
}

func TestCheckGitRepo_Valid(t *testing.T) {
	dir := chdirTemp(t)
	gitInit(t, dir)
	gitCommit(t, dir)
	r := checkGitRepo()
	if !r.Passed {
		t.Errorf("expected passed, got: %s", r.Message)
	}
}

func TestCheckGitRepo_NoGit(t *testing.T) {
	dir := chdirTemp(t)
	_ = dir
	r := checkGitRepo()
	if r.Passed {
		t.Error("expected not passed without git repo")
	}
}

func TestCheckGitRepo_EmptyRepo(t *testing.T) {
	dir := chdirTemp(t)
	gitInit(t, dir)
	r := checkGitRepo()
	if !r.Passed {
		t.Errorf("expected passed (no commits still ok), got: %s", r.Message)
	}
}

func TestCheckLLMKey_Configured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	if err := os.WriteFile(path, []byte("version: 1\nllm:\n  provider: openai\n  api_key: sk-test123\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkLLMKey(path)
	if !r.Passed {
		t.Errorf("expected passed, got: %s", r.Message)
	}
}

func TestCheckLLMKey_NoProvider(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	if err := os.WriteFile(path, []byte("version: 1\nllm:\n  provider: ''\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkLLMKey(path)
	if !r.Passed {
		t.Errorf("expected passed when no provider, got: %s", r.Message)
	}
}

func TestCheckLLMKey_NoKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	if err := os.WriteFile(path, []byte("version: 1\nllm:\n  provider: openai\n  api_key: ''\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkLLMKey(path)
	if r.Passed {
		t.Error("expected not passed when provider has no key")
	}
}

func TestCheckLLMKey_SkipsOnBadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".trusty.yml")
	if err := os.WriteFile(path, []byte(": : invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkLLMKey(path)
	if !r.Passed {
		t.Errorf("expected passed (skip LLM check), got: %s", r.Message)
	}
}

func TestCheckLLMKey_FindsConfigInCWD(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, ".trusty.yml"), []byte("version: 1\nllm:\n  provider: anthropic\n  api_key: sk-ant-test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkLLMKey("")
	if !r.Passed {
		t.Errorf("expected passed, got: %s", r.Message)
	}
}

func TestCheckGitHooks_NoGit(t *testing.T) {
	dir := chdirTemp(t)
	_ = dir
	r := checkGitHooks()
	if !r.Passed {
		t.Errorf("expected passed when no git, got: %s", r.Message)
	}
}

func TestCheckGitHooks_NoHook(t *testing.T) {
	dir := chdirTemp(t)
	gitInit(t, dir)
	r := checkGitHooks()
	if !r.Passed {
		t.Errorf("expected passed without hook, got: %s", r.Message)
	}
}

func TestCheckGitHooks_TrustyHook(t *testing.T) {
	dir := chdirTemp(t)
	gitInit(t, dir)
	hookDir := filepath.Join(dir, ".git", "hooks")
	os.MkdirAll(hookDir, 0755)
	if err := os.WriteFile(filepath.Join(hookDir, "pre-commit"), []byte("#!/bin/sh\ntrusty scan\n"), 0755); err != nil {
		t.Fatal(err)
	}
	r := checkGitHooks()
	if !r.Passed {
		t.Errorf("expected passed with trusty hook, got: %s", r.Message)
	}
}

func TestCheckGitHooks_OtherHook(t *testing.T) {
	dir := chdirTemp(t)
	gitInit(t, dir)
	hookDir := filepath.Join(dir, ".git", "hooks")
	os.MkdirAll(hookDir, 0755)
	if err := os.WriteFile(filepath.Join(hookDir, "pre-commit"), []byte("#!/bin/sh\necho lint\n"), 0755); err != nil {
		t.Fatal(err)
	}
	r := checkGitHooks()
	if !r.Passed {
		t.Errorf("expected passed with other hook, got: %s", r.Message)
	}
}

func TestCheckGitignore_NoFile(t *testing.T) {
	dir := chdirTemp(t)
	_ = dir
	r := checkGitignore()
	if !r.Passed {
		t.Errorf("expected passed without .gitignore, got: %s", r.Message)
	}
}

func TestCheckGitignore_MissingEntries(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.log\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkGitignore()
	if !r.Passed {
		t.Errorf("expected passed with missing entries, got: %s", r.Message)
	}
}

func TestCheckGitignore_AllEntries(t *testing.T) {
	dir := chdirTemp(t)
	content := ".trusty-cache.json\n.trusty-history.json\n.trusty-audit.jsonl\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkGitignore()
	if !r.Passed {
		t.Errorf("expected passed with all entries, got: %s", r.Message)
	}
}

func TestCheckCacheFiles_ValidJSON(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, ".trusty-cache.json"), []byte(`{"key": "value"}`), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkCacheFiles()
	if !r.Passed {
		t.Errorf("expected passed, got: %s", r.Message)
	}
}

func TestCheckCacheFiles_InvalidJSON(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, ".trusty-cache.json"), []byte(`not json`), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkCacheFiles()
	if r.Passed {
		t.Error("expected not passed for invalid JSON")
	}
}

func TestCheckCacheFiles_Nonexistent(t *testing.T) {
	dir := chdirTemp(t)
	_ = dir
	r := checkCacheFiles()
	if !r.Passed {
		t.Errorf("expected passed with no cache files, got: %s", r.Message)
	}
}

func TestCheckCacheFiles_HistoryAndAuditValid(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, ".trusty-history.json"), []byte(`{"scores": []}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".trusty-audit.jsonl"), []byte(`{"event": "test"}`), 0644); err != nil {
		t.Fatal(err)
	}
	r := checkCacheFiles()
	if !r.Passed {
		t.Errorf("expected passed, got: %s", r.Message)
	}
}

func TestRun_AllPass(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, ".trusty.yml"), []byte("version: 1\nllm:\n  provider: openai\n  api_key: test123\n"), 0644); err != nil {
		t.Fatal(err)
	}
	gitInit(t, dir)
	gitCommit(t, dir)

	r := Run("")
	if r == nil {
		t.Fatal("Run returned nil")
	}
	if !r.Passed {
		t.Errorf("expected all passed, got message: %s", r.Message)
	}
}

func TestRun_SomeFail(t *testing.T) {
	dir := chdirTemp(t)
	_ = dir

	r := Run("")
	if r == nil {
		t.Fatal("Run returned nil")
	}
	if r.Passed {
		t.Errorf("expected some checks to fail outside git repo, got message: %s", r.Message)
	}
	if len(r.Checks) == 0 {
		t.Error("expected at least one check result")
	}
}

func TestRun_WithConfigPath(t *testing.T) {
	dir := chdirTemp(t)
	cfgPath := filepath.Join(dir, "custom.yml")
	if err := os.WriteFile(cfgPath, []byte("version: 1\nllm:\n  provider: openai\n  api_key: test-key-123\nscan:\n  min_score: 90\n"), 0644); err != nil {
		t.Fatal(err)
	}
	gitInit(t, dir)
	gitCommit(t, dir)

	r := Run(cfgPath)
	if r == nil {
		t.Fatal("Run returned nil")
	}
	if !r.Passed {
		t.Errorf("expected all passed, got: %s", r.Message)
	}
}

func TestCheckResult_Fields(t *testing.T) {
	r := CheckResult{Name: "test-check", Passed: true, Message: "all good"}
	if r.Name != "test-check" {
		t.Errorf("Name = %q", r.Name)
	}
	if !r.Passed {
		t.Error("Passed should be true")
	}
	if r.Message != "all good" {
		t.Errorf("Message = %q", r.Message)
	}
}
