package ci

import (
	"context"
	"fmt"
	"os"

	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/types"
)

type Platform string

const (
	PlatformGitHubActions Platform = "github-actions"
	PlatformGitLabCI      Platform = "gitlab-ci"
	PlatformJenkins       Platform = "jenkins"
	PlatformCircleCI      Platform = "circleci"
	PlatformLocal         Platform = "local"
)

type Pipeline struct {
	Platform Platform
	ScanOnly bool
}

func Detect() Pipeline {
	switch {
	case os.Getenv("GITHUB_ACTIONS") == "true":
		return Pipeline{Platform: PlatformGitHubActions, ScanOnly: false}
	case os.Getenv("GITLAB_CI") == "true":
		return Pipeline{Platform: PlatformGitLabCI, ScanOnly: false}
	case os.Getenv("JENKINS_URL") != "" || os.Getenv("JENKINS_HOME") != "":
		return Pipeline{Platform: PlatformJenkins, ScanOnly: true}
	case os.Getenv("CIRCLECI") == "true":
		return Pipeline{Platform: PlatformCircleCI, ScanOnly: true}
	default:
		return Pipeline{Platform: PlatformLocal, ScanOnly: true}
	}
}

func (p Pipeline) String() string {
	switch p.Platform {
	case PlatformGitHubActions:
		return "GitHub Actions"
	case PlatformGitLabCI:
		return "GitLab CI"
	case PlatformJenkins:
		return "Jenkins"
	case PlatformCircleCI:
		return "CircleCI"
	default:
		return "Local"
	}
}

type Result struct {
	ScanResult  *types.ScanResult
	Passed      bool
	Message     string
	CommentSent bool
}

func Run(ctx context.Context, cfg *config.Config) (*Result, error) {
	pipeline := Detect()
	fmt.Fprintf(os.Stderr, "Detected CI platform: %s\n", pipeline)

	s := scanner.NewScanner(cfg, nil)

	diffOpts := types.DiffOptions{
		Staged: true,
	}

	scanResult, err := s.Scan(ctx, diffOpts)
	s.FlushCache()
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	r := &Result{
		ScanResult: scanResult,
		Passed:     scanResult.Summary.TotalIssues == 0,
		Message:    fmt.Sprintf("Trust score: %d/100 | Issues: %d", scanResult.TrustScore, scanResult.Summary.TotalIssues),
	}

	fmt.Fprintf(os.Stderr, "Trust score: %d/100 | Issues: %d\n", scanResult.TrustScore, scanResult.Summary.TotalIssues)

	for _, f := range scanResult.Files {
		for _, finding := range f.Findings {
			sev := "INFO"
			switch finding.Severity {
			case types.SeverityError:
				sev = "ERROR"
			case types.SeverityWarning:
				sev = "WARN"
			}
			fmt.Fprintf(os.Stderr, "  [%s] %s:%d %s\n", sev, f.Path, finding.Line, finding.Message)
		}
	}

	if pipeline.ScanOnly {
		return r, nil
	}

	switch pipeline.Platform {
	case PlatformGitHubActions:
		if err := postGitHubComment(scanResult); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to post GitHub comment: %v\n", err)
		} else {
			r.CommentSent = true
		}
	case PlatformGitLabCI:
		if err := postGitLabComment(scanResult); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to post GitLab comment: %v\n", err)
		} else {
			r.CommentSent = true
		}
	}

	return r, nil
}

func postGitHubComment(result *types.ScanResult) error {
	token := os.Getenv("GITHUB_TOKEN")
	repo := os.Getenv("GITHUB_REPOSITORY")
	prNum := os.Getenv("GITHUB_PR_NUMBER")

	if token == "" || repo == "" || prNum == "" {
		return fmt.Errorf("GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_PR_NUMBER must be set")
	}

	body := buildCommentBody(result, "GitHub")
	return postComment(token, repo, prNum, body, "github")
}

func postGitLabComment(result *types.ScanResult) error {
	token := os.Getenv("GITLAB_TOKEN")
	projectID := os.Getenv("CI_PROJECT_ID")
	mrIID := os.Getenv("CI_MERGE_REQUEST_IID")

	if token == "" || projectID == "" || mrIID == "" {
		return fmt.Errorf("GITLAB_TOKEN, CI_PROJECT_ID, and CI_MERGE_REQUEST_IID must be set")
	}

	body := buildCommentBody(result, "GitLab")
	return postComment(token, projectID, mrIID, body, "gitlab")
}
