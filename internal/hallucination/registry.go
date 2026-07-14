package hallucination

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Registry struct {
	client  *http.Client
	cache   map[string]bool
	mu      sync.RWMutex
}

func NewRegistry() *Registry {
	return &Registry{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		cache: make(map[string]bool),
	}
}

func (r *Registry) CheckGoModule(importPath string) bool {
	r.mu.RLock()
	if exists, ok := r.cache[importPath]; ok {
		r.mu.RUnlock()
		return exists
	}
	r.mu.RUnlock()

	exists := r.checkGoProxy(importPath)

	r.mu.Lock()
	r.cache[importPath] = exists
	r.mu.Unlock()

	return exists
}

func (r *Registry) checkGoProxy(importPath string) bool {
	modulePath := importPath
	if idx := strings.Index(importPath, "/"); idx >= 0 {
		parts := strings.Split(importPath, "/")
		if len(parts) >= 3 && strings.Contains(parts[0], ".") {
			modulePath = strings.Join(parts[:3], "/")
		} else if len(parts) >= 2 {
			modulePath = strings.Join(parts[:2], "/")
		}
	}

	url := fmt.Sprintf("https://proxy.golang.org/%s/@latest", modulePath)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return true
	}
	req.Header.Set("User-Agent", "Trusty/1.0")

	resp, err := r.client.Do(req)
	if err != nil {
		return true
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func (r *Registry) CheckPyPI(packageName string) bool {
	r.mu.RLock()
	if exists, ok := r.cache["pypi:"+packageName]; ok {
		r.mu.RUnlock()
		return exists
	}
	r.mu.RUnlock()

	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", packageName)
	resp, err := r.client.Get(url)
	if err != nil {
		return true
	}
	defer resp.Body.Close()

	exists := resp.StatusCode == 200

	r.mu.Lock()
	r.cache["pypi:"+packageName] = exists
	r.mu.Unlock()

	return exists
}

func (r *Registry) CheckNPM(packageName string) bool {
	r.mu.RLock()
	if exists, ok := r.cache["npm:"+packageName]; ok {
		r.mu.RUnlock()
		return exists
	}
	r.mu.RUnlock()

	url := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)
	resp, err := r.client.Get(url)
	if err != nil {
		return true
	}
	defer resp.Body.Close()

	exists := resp.StatusCode == 200

	r.mu.Lock()
	r.cache["npm:"+packageName] = exists
	r.mu.Unlock()

	return exists
}
