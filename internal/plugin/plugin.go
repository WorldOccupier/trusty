package plugin

import (
	"fmt"
	"plugin"
	"sync"

	"github.com/WorldOccupier/trusty/internal/types"
)

type Checker interface {
	Name() string
	Check(file types.DiffFile) ([]types.Finding, error)
}

type Registry struct {
	mu       sync.RWMutex
	checkers map[string]Checker
}

func NewRegistry() *Registry {
	return &Registry{
		checkers: make(map[string]Checker),
	}
}

func (r *Registry) Register(c Checker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checkers[c.Name()] = c
}

func (r *Registry) Get(name string) (Checker, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.checkers[name]
	return c, ok
}

func (r *Registry) All() []Checker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Checker, 0, len(r.checkers))
	for _, c := range r.checkers {
		result = append(result, c)
	}
	return result
}

func LoadPlugin(path string) (Checker, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening plugin %s: %w", path, err)
	}

	sym, err := p.Lookup("NewChecker")
	if err != nil {
		return nil, fmt.Errorf("plugin %s missing NewChecker symbol: %w", path, err)
	}

	newFunc, ok := sym.(func() Checker)
	if !ok {
		return nil, fmt.Errorf("plugin %s NewChecker has wrong signature", path)
	}

	return newFunc(), nil
}
