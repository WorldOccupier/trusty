package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/WorldOccupier/trusty/internal/types"
)

type CacheEntry struct {
	ContentHash string          `json:"content_hash"`
	Findings    []types.Finding `json:"findings"`
	Score       int             `json:"score"`
	ScannedAt   string          `json:"scanned_at"`
}

type ScanCache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
	path    string
	enabled bool
}

func NewScanCache(cachePath string) *ScanCache {
	if cachePath == "" {
		cachePath = ".trusty-cache.json"
	}
	c := &ScanCache{
		entries: make(map[string]CacheEntry),
		path:    cachePath,
		enabled: true,
	}
	c.load()
	return c
}

func (c *ScanCache) Enabled() bool {
	return c.enabled
}

func (c *ScanCache) SetEnabled(enabled bool) {
	c.enabled = enabled
}

func (c *ScanCache) contentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", h)
}

func (c *ScanCache) Get(path, content string) ([]types.Finding, int, bool) {
	if !c.enabled {
		return nil, 0, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[path]
	if !ok {
		return nil, 0, false
	}

	if entry.ContentHash != c.contentHash(content) {
		return nil, 0, false
	}

	return entry.Findings, entry.Score, true
}

func (c *ScanCache) Set(path, content string, findings []types.Finding, score int) {
	if !c.enabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[path] = CacheEntry{
		ContentHash: c.contentHash(content),
		Findings:    findings,
		Score:       score,
		ScannedAt:   time.Now().UTC().Format(time.RFC3339),
	}
}

func (c *ScanCache) Invalidate(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, path)
}

func (c *ScanCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]CacheEntry)
	c.save()
}

func (c *ScanCache) load() {
	data, err := os.ReadFile(filepath.Clean(c.path))
	if err != nil {
		return
	}
	var entries map[string]CacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	c.entries = entries
}

func (c *ScanCache) save() {
	if !c.enabled {
		return
	}
	data, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(filepath.Clean(c.path), data, 0644)
}

func (c *ScanCache) Flush() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.save()
}

type cachedFileResult struct {
	findings []types.Finding
	score    int
	cached   bool
}
