package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/WorldOccupier/trusty/internal/audit"
	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/dashboard"
	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/sso"
	"github.com/WorldOccupier/trusty/internal/types"
)

type Server struct {
	port    int
	cfg     *config.Config
	sso     *sso.Authenticator
	audit   *audit.Trail
	mu      sync.RWMutex
	clients map[chan string]struct{}
}

func New(cfg *config.Config, port int) *Server {
	return &Server{
		port:    port,
		cfg:     cfg,
		audit:   audit.New(".trusty-audit.jsonl"),
		clients: make(map[chan string]struct{}),
	}
}

func (s *Server) SetSSO(a *sso.Authenticator) {
	s.sso = a
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/events", s.handleSSE)

	handler := http.Handler(mux)
	if s.sso != nil {
		handler = s.sso.Middleware(handler)
	}

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Trusty web server starting on %s", addr)
	log.Printf("  Dashboard: http://localhost%s", addr)
	log.Printf("  Health:    http://localhost%s/api/health", addr)
	log.Printf("  API:       http://localhost%s/api/stats", addr)

	return http.ListenAndServe(addr, handler)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html, err := dashboard.Generate(".trusty-audit.jsonl")
	if err != nil {
		log.Printf("dashboard error: %v", err)
		html = s.fallbackDashboard()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func (s *Server) fallbackDashboard() string {
	return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Trusty Dashboard</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0d1117; color:#c9d1d9; padding:24px; }
h1 { color:#00FF88; font-size:28px; margin-bottom:16px; }
p { color:#8b949e; font-size:16px; }
</style></head>
<body>
<h1>Trusty Dashboard</h1>
<p>No audit data yet. Run <code>trusty scan --track</code> to populate.</p>
</body></html>`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"version": "1.0.0",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	data, err := dashboard.WriteJSON(".trusty-audit.jsonl")
	if err != nil {
		http.Error(w, `{"error":"no audit data"}`, http.StatusNotFound)
		return
	}

	fmt.Fprint(w, data)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	diffOpts := types.DiffOptions{
		Staged: true,
	}

	var llmProvider llm.Provider
	if s.cfg.LLM.APIKey != "" {
		llmCfg := llm.ProviderConfig{
			Model:       s.cfg.LLM.Model,
			Temperature: s.cfg.LLM.Temperature,
			APIKey:      s.cfg.LLM.APIKey,
			BaseURL:     s.cfg.LLM.BaseURL,
		}
		llmProvider = llm.NewProvider(s.cfg.LLM.Provider, llmCfg)
	}

	sc := scanner.NewScanner(s.cfg, llmProvider)
	result, err := sc.Scan(context.Background(), diffOpts)
	sc.FlushCache()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	s.broadcast(fmt.Sprintf("scan complete: score=%d issues=%d", result.TrustScore, result.Summary.TotalIssues))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 64)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (s *Server) broadcast(msg string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}


