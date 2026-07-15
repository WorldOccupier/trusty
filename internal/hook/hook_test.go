package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallCreatesHookFile(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := Install(dir, PreCommit, false); err != nil {
		t.Fatal(err)
	}

	path := hookPath(dir, PreCommit)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("hook file was not created")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "trusty scan --staged") {
		t.Error("hook script missing expected content")
	}
}

func TestInstallWithoutGitDirReturnsError(t *testing.T) {
	dir := t.TempDir()

	err := Install(dir, PreCommit, false)
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInstallExistingWithoutForceReturnsError(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := Install(dir, PreCommit, false); err != nil {
		t.Fatal(err)
	}

	err := Install(dir, PreCommit, false)
	if err == nil {
		t.Fatal("expected error when hook already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInstallWithForceOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := Install(dir, PreCommit, false); err != nil {
		t.Fatal(err)
	}

	if err := Install(dir, PreCommit, true); err != nil {
		t.Fatalf("force install should not error: %v", err)
	}

	path := hookPath(dir, PreCommit)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "trusty scan --staged") {
		t.Error("hook file content is wrong after force install")
	}
}

func TestInstallPrePush(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := Install(dir, PrePush, false); err != nil {
		t.Fatal(err)
	}

	path := hookPath(dir, PrePush)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("pre-push hook file was not created")
	}
}

func TestUninstallRemovesHookFile(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := Install(dir, PreCommit, false); err != nil {
		t.Fatal(err)
	}

	if err := Uninstall(dir, PreCommit); err != nil {
		t.Fatal(err)
	}

	path := hookPath(dir, PreCommit)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("hook file was not removed")
	}
}

func TestUninstallNonExistentReturnsError(t *testing.T) {
	dir := t.TempDir()

	err := Uninstall(dir, PreCommit)
	if err == nil {
		t.Fatal("expected error when no hook exists")
	}
	if !strings.Contains(err.Error(), "no") || !strings.Contains(err.Error(), "hook found") {
		t.Errorf("unexpected error: %v", err)
	}
}
