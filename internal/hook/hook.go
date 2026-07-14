package hook

import (
	"fmt"
	"os"
	"path/filepath"
)

type Type string

const (
	PreCommit Type = "pre-commit"
	PrePush   Type = "pre-push"
)

func hookScript() string {
	return `#!/bin/sh
# Trusty pre-commit hook — verify AI-generated code before committing
exec trusty scan --staged
`
}

func hookPath(dir string, t Type) string {
	return filepath.Join(dir, ".git", "hooks", string(t))
}

func Install(dir string, t Type, force bool) error {
	gitDir := filepath.Join(dir, ".git")
	info, err := os.Stat(gitDir)
	if err != nil {
		return fmt.Errorf("not a git repository: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("not a git repository: %s is not a directory", gitDir)
	}

	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("creating hooks directory: %w", err)
	}

	path := hookPath(dir, t)
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("hook already exists at %s (use --force to overwrite)", path)
	}

	if err := os.WriteFile(path, []byte(hookScript()), 0755); err != nil {
		return fmt.Errorf("writing hook: %w", err)
	}

	fmt.Printf("Installed %s hook at %s\n", t, path)
	return nil
}

func Uninstall(dir string, t Type) error {
	path := hookPath(dir, t)
	if err := os.Remove(path); os.IsNotExist(err) {
		return fmt.Errorf("no %s hook found at %s", t, path)
	} else if err != nil {
		return fmt.Errorf("removing hook: %w", err)
	}

	fmt.Printf("Removed %s hook from %s\n", t, path)
	return nil
}
