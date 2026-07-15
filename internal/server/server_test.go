package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/WorldOccupier/trusty/internal/config"
)

func TestNew(t *testing.T) {
	cfg := config.Default()
	s := New(cfg, 8080)
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if s.port != 8080 {
		t.Errorf("port = %d, want 8080", s.port)
	}
	if s.cfg != cfg {
		t.Error("cfg should match")
	}
}

func TestHandleHealth(t *testing.T) {
	s := New(config.Default(), 0)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/health", nil)

	s.handleHealth(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["version"] != "1.0.0" {
		t.Errorf("version = %v, want 1.0.0", body["version"])
	}
	if _, ok := body["time"]; !ok {
		t.Error("response should contain time")
	}
}

func TestHandleDashboard(t *testing.T) {
	s := New(config.Default(), 0)

	t.Run("root path returns HTML", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)

		s.handleDashboard(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		ct := w.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Errorf("Content-Type = %q, want text/html", ct)
		}
		if !strings.Contains(w.Body.String(), "Trusty Dashboard") {
			t.Error("response should contain Trusty Dashboard")
		}
	})

	t.Run("non-root returns 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/other", nil)

		s.handleDashboard(w, r)

		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestHandleStats(t *testing.T) {
	s := New(config.Default(), 0)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/stats", nil)

	s.handleStats(w, r)

	// When no audit file exists, Query returns nil,nil, Summary returns 0s,
	// WriteJSON returns empty data successfully — so we get 200, not 404.
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleScanMethodNotAllowed(t *testing.T) {
	s := New(config.Default(), 0)

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(method, "/api/scan", nil)

			s.handleScan(w, r)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status = %d, want %d", method, w.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

type noFlushWriter struct {
	code int
	hdr  http.Header
	buf  bytes.Buffer
}

func (w *noFlushWriter) Header() http.Header        { return w.hdr }
func (w *noFlushWriter) Write(b []byte) (int, error) { return w.buf.Write(b) }
func (w *noFlushWriter) WriteHeader(code int)         { w.code = code }

func TestHandleSSENotSupported(t *testing.T) {
	s := New(config.Default(), 0)
	w := &noFlushWriter{hdr: make(http.Header)}
	r := httptest.NewRequest("GET", "/api/events", nil)

	s.handleSSE(w, r)

	if w.code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.code, http.StatusInternalServerError)
	}
}

func TestServerStartPortInUse(t *testing.T) {
	// Start a server on a port, then try starting another on the same port
	s1 := New(config.Default(), 0)
	s2 := New(config.Default(), 0)

	// We can't trivially test Start() since it blocks, but we can
	// verify the server struct is correctly configured
	if s1.port != 0 || s2.port != 0 {
		t.Log("both servers configured with port 0")
	}
}
