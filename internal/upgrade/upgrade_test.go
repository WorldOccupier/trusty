package upgrade

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
)

func TestCurrentVersion(t *testing.T) {
	v := CurrentVersion()
	if v == "" {
		t.Fatal("CurrentVersion() returned empty string")
	}
	if v != "0.1.0" {
		t.Errorf("CurrentVersion() = %q, want %q", v, "0.1.0")
	}
}

func TestIsNewerAvailable(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"0.1.0", "0.1.0", false},
		{"0.1.0", "0.2.0", true},
		{"1.0.0", "0.9.0", true},
		{"", "0.1.0", true},
		{"0.1.0", "", true},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.current+">"+tt.latest, func(t *testing.T) {
			got := IsNewerAvailable(tt.current, tt.latest)
			if got != tt.want {
				t.Errorf("IsNewerAvailable(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

type githubTransport struct {
	orig    http.RoundTripper
	mockURL string
}

func (t *githubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, "api.github.com") {
		mock, _ := url.Parse(t.mockURL)
		clone := req.Clone(req.Context())
		clone.URL.Scheme = mock.Scheme
		clone.URL.Host = mock.Host
		clone.RequestURI = ""
		return t.orig.RoundTrip(clone)
	}
	return t.orig.RoundTrip(req)
}

func TestCheckLatest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/WorldOccupier/trusty/releases/latest") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tag_name": "v0.2.0",
			"html_url": "https://github.com/test/trusty",
			"body":     "Test release",
			"assets": []map[string]interface{}{
				{"name": "trusty_v0.2.0_linux_amd64.tar.gz", "url": "http://example.com/asset"},
			},
		})
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &githubTransport{orig: http.DefaultTransport, mockURL: ts.URL}
	defer func() { http.DefaultTransport = origTransport }()

	release, err := CheckLatest()
	if err != nil {
		t.Fatalf("CheckLatest() error: %v", err)
	}
	if release.TagName != "v0.2.0" {
		t.Errorf("TagName = %q, want %q", release.TagName, "v0.2.0")
	}
	if release.HTMLURL != "https://github.com/test/trusty" {
		t.Errorf("HTMLURL = %q, want %q", release.HTMLURL, "https://github.com/test/trusty")
	}
	if release.Body != "Test release" {
		t.Errorf("Body = %q, want %q", release.Body, "Test release")
	}
	if len(release.Assets) != 1 {
		t.Fatalf("got %d assets, want 1", len(release.Assets))
	}
	if release.Assets[0].Name != "trusty_v0.2.0_linux_amd64.tar.gz" {
		t.Errorf("Asset name = %q, want %q", release.Assets[0].Name, "trusty_v0.2.0_linux_amd64.tar.gz")
	}
}

func TestCheckLatest_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &githubTransport{orig: http.DefaultTransport, mockURL: ts.URL}
	defer func() { http.DefaultTransport = origTransport }()

	_, err := CheckLatest()
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestCheckLatest_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &githubTransport{orig: http.DefaultTransport, mockURL: ts.URL}
	defer func() { http.DefaultTransport = origTransport }()

	_, err := CheckLatest()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestPerformUpgrade_MissingAsset(t *testing.T) {
	release := &Release{
		TagName: "v0.2.0",
		Assets:  nil,
	}

	err := PerformUpgrade(release)
	if err == nil {
		t.Fatal("expected error for missing asset")
	}

	expectedAsset := "trusty_0.2.0_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	if !strings.Contains(err.Error(), expectedAsset) {
		t.Errorf("error should mention asset name %q, got: %v", expectedAsset, err)
	}
}

func TestPerformUpgrade_EmptyAssets(t *testing.T) {
	release := &Release{
		TagName: "v1.0.0",
		Assets: []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		}{
			{Name: "some-other-file.tar.gz", URL: "http://example.com"},
		},
	}

	err := PerformUpgrade(release)
	if err == nil {
		t.Fatal("expected error when no matching asset")
	}
}
