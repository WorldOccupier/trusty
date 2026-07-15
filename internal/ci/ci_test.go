package ci

import (
	"os"
	"testing"
)

func TestDetect_Local(t *testing.T) {
	// Save and clear CI env vars to ensure local detection
	ciVars := []string{"GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "JENKINS_HOME", "CIRCLECI"}
	saved := make(map[string]string)
	for _, v := range ciVars {
		saved[v] = os.Getenv(v)
		os.Unsetenv(v)
	}
	defer func() {
		for k, v := range saved {
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}()

	p := Detect()
	if p.Platform != PlatformLocal {
		t.Errorf("expected Local, got %s", p.Platform)
	}
	if !p.ScanOnly {
		t.Errorf("expected ScanOnly=true for local")
	}
}

func TestDetect_GitHubActions(t *testing.T) {
	os.Setenv("GITHUB_ACTIONS", "true")
	defer os.Unsetenv("GITHUB_ACTIONS")

	p := Detect()
	if p.Platform != PlatformGitHubActions {
		t.Errorf("expected GitHubActions, got %s", p.Platform)
	}
	if p.ScanOnly {
		t.Errorf("expected ScanOnly=false for GitHub Actions")
	}
}

func TestDetect_GitLabCI(t *testing.T) {
	os.Setenv("GITLAB_CI", "true")
	defer os.Unsetenv("GITLAB_CI")

	p := Detect()
	if p.Platform != PlatformGitLabCI {
		t.Errorf("expected GitLabCI, got %s", p.Platform)
	}
	if p.ScanOnly {
		t.Errorf("expected ScanOnly=false for GitLab CI")
	}
}

func TestDetect_Jenkins(t *testing.T) {
	os.Setenv("JENKINS_URL", "http://jenkins:8080")
	defer os.Unsetenv("JENKINS_URL")

	p := Detect()
	if p.Platform != PlatformJenkins {
		t.Errorf("expected Jenkins, got %s", p.Platform)
	}
	if !p.ScanOnly {
		t.Errorf("expected ScanOnly=true for Jenkins")
	}
}

func TestDetect_CircleCI(t *testing.T) {
	os.Setenv("CIRCLECI", "true")
	defer os.Unsetenv("CIRCLECI")

	p := Detect()
	if p.Platform != PlatformCircleCI {
		t.Errorf("expected CircleCI, got %s", p.Platform)
	}
}

func TestPipeline_String(t *testing.T) {
	tests := []struct {
		p    Pipeline
		want string
	}{
		{Pipeline{Platform: PlatformGitHubActions}, "GitHub Actions"},
		{Pipeline{Platform: PlatformGitLabCI}, "GitLab CI"},
		{Pipeline{Platform: PlatformJenkins}, "Jenkins"},
		{Pipeline{Platform: PlatformCircleCI}, "CircleCI"},
		{Pipeline{Platform: PlatformLocal}, "Local"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
