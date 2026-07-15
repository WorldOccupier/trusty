package plugin

import (
	"strings"
	"testing"

	"github.com/WorldOccupier/trusty/internal/types"
)

type mockChecker struct {
	name string
}

func (m *mockChecker) Name() string {
	return m.name
}

func (m *mockChecker) Check(file types.DiffFile) ([]types.Finding, error) {
	return nil, nil
}

func TestNewRegistryCreatesEmpty(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	all := r.All()
	if len(all) != 0 {
		t.Errorf("expected empty registry, got %d checkers", len(all))
	}
}

func TestRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	c := &mockChecker{name: "test-checker"}
	r.Register(c)

	got, ok := r.Get("test-checker")
	if !ok {
		t.Fatal("expected to find registered checker")
	}
	if got.Name() != "test-checker" {
		t.Errorf("expected name 'test-checker', got %s", got.Name())
	}
}

func TestGetNonExistent(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Get("nonexistent")
	if ok {
		t.Fatal("expected false for non-existent checker")
	}
}

func TestAllReturnsAllCheckers(t *testing.T) {
	r := NewRegistry()
	c1 := &mockChecker{name: "checker-one"}
	c2 := &mockChecker{name: "checker-two"}
	r.Register(c1)
	r.Register(c2)

	all := r.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 checkers, got %d", len(all))
	}

	names := map[string]bool{}
	for _, c := range all {
		names[c.Name()] = true
	}
	if !names["checker-one"] {
		t.Error("missing checker-one")
	}
	if !names["checker-two"] {
		t.Error("missing checker-two")
	}
}

func TestAllReturnsCopy(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockChecker{name: "a"})
	r.Register(&mockChecker{name: "b"})

	all := r.All()
	r.Register(&mockChecker{name: "c"})

	if len(all) != 2 {
		t.Error("All() should return a snapshot, not a live view")
	}
}

func TestRegisterOverwritesDuplicate(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockChecker{name: "dup"})
	r.Register(&mockChecker{name: "dup"})

	all := r.All()
	if len(all) != 1 {
		t.Errorf("expected 1 checker after overwrite, got %d", len(all))
	}
}

func TestLoadPluginNonExistentFile(t *testing.T) {
	_, err := LoadPlugin("/nonexistent/plugin.so")
	if err == nil {
		t.Fatal("expected error for non-existent plugin file")
	}
	if !strings.Contains(err.Error(), "opening plugin") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRegistryConcurrencySafe(t *testing.T) {
	r := NewRegistry()
	c := &mockChecker{name: "concurrent"}
	r.Register(c)

	done := make(chan bool)
	go func() {
		r.Register(&mockChecker{name: "from-goroutine"})
		done <- true
	}()
	go func() {
		r.Get("concurrent")
		done <- true
	}()
	go func() {
		r.All()
		done <- true
	}()

	for i := 0; i < 3; i++ {
		<-done
	}
}

func TestMockCheckerImplementsInterface(t *testing.T) {
	var _ Checker = (*mockChecker)(nil)
}
