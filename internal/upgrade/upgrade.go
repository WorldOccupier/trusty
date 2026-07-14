package upgrade

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const version = "0.1.0"

const repo = "WorldOccupier/trusty"

type Release struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Body    string `json:"body"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"assets"`
}

func CurrentVersion() string {
	return version
}

func CheckLatest() (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parsing release: %w", err)
	}

	return &release, nil
}

func IsNewerAvailable(current, latest string) bool {
	return current != latest
}

func PerformUpgrade(release *Release) error {
	assetName := fmt.Sprintf("trusty_%s_%s_%s.tar.gz", strings.TrimPrefix(release.TagName, "v"), runtime.GOOS, runtime.GOARCH)

	var downloadURL string
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.URL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no asset found for %s/%s: %s", runtime.GOOS, runtime.GOARCH, assetName)
	}

	return installViaGo()
}

func installViaGo() error {
	cmd := exec.Command("go", "install", fmt.Sprintf("github.com/%s/cmd/trusty@latest", repo))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath.Clean(dest))
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
