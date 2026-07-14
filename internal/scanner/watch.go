package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/types"
)

type Watcher struct {
	cfg     *config.Config
	scanner *Scanner
	dirs    []string
}

func NewWatcher(cfg *config.Config, s *Scanner, dirs []string) *Watcher {
	return &Watcher{cfg: cfg, scanner: s, dirs: dirs}
}

func (w *Watcher) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}
	defer watcher.Close()

	watchDirs := w.resolveDirs()
	for _, dir := range watchDirs {
		if err := watcher.Add(dir); err != nil {
			return fmt.Errorf("watching %s: %w", dir, err)
		}
	}

	debounce := time.NewTimer(0)
	if !debounce.Stop() {
		<-debounce.C
	}
	debounceCh := make(chan struct{}, 1)

	fmt.Fprintf(os.Stderr, "🔍 Watching %d directories for changes...\n", len(watchDirs))
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop.\n\n")

	w.runScan(ctx)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !w.shouldIgnore(event.Name) {
				debounce.Reset(300 * time.Millisecond)
				select {
				case debounceCh <- struct{}{}:
				default:
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(os.Stderr, "watch error: %v\n", err)

		case <-debounceCh:
			<-debounce.C
			w.runScan(ctx)

		case <-ctx.Done():
			return nil
		}
	}
}

func (w *Watcher) resolveDirs() []string {
	if len(w.dirs) > 0 {
		return w.dirs
	}
	return []string{"."}
}

func (w *Watcher) shouldIgnore(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") {
		return true
	}
	ext := filepath.Ext(path)
	switch ext {
	case ".go", ".py", ".js", ".ts", ".tsx", ".jsx", ".yaml", ".yml", ".json", ".mod", ".sum":
		return false
	}
	return true
}

func (w *Watcher) runScan(ctx context.Context) {
	opts := types.DiffOptions{Path: "."}
	files, err := GetDiff(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		return
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no files changed\n")
		return
	}

	result, err := w.scanner.Scan(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "\n--- Scan at %s ---\n", result.Timestamp)
	fmt.Fprintf(os.Stderr, "Files: %d, Issues: %d, Score: %d/100, Status: %s\n",
		result.Summary.FilesScanned, result.Summary.TotalIssues, result.TrustScore, result.Summary.Status)

	for _, fr := range result.Files {
		for _, f := range fr.Findings {
			sev := "INFO"
			switch f.Severity {
			case types.SeverityError:
				sev = "ERROR"
			case types.SeverityWarning:
				sev = "WARN"
			}
			fmt.Fprintf(os.Stderr, "  [%s] %s:%d %s\n", sev, fr.Path, f.Line, f.Message)
		}
	}
	fmt.Fprintln(os.Stderr)
}
