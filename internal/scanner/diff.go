package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/user/trustpilot/internal/types"
)

func isGitRepo() bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

func hasHEAD() bool {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	return cmd.Run() == nil
}

func GetDiff(opts types.DiffOptions) ([]types.DiffFile, error) {
	if !isGitRepo() {
		return scanDirectory(".")
	}

	if !hasHEAD() {
		return scanDirectory(".")
	}

	args := []string{"diff"}

	if opts.Staged {
		args = append(args, "--cached")
	} else if opts.From != "" && opts.To != "" {
		args = append(args, fmt.Sprintf("%s..%s", opts.From, opts.To))
	} else if opts.Base != "" && opts.Head != "" {
		args = append(args, fmt.Sprintf("%s...%s", opts.Base, opts.Head))
	} else {
		args = append(args, "HEAD")
	}

	args = append(args, "--unified=10", "--diff-filter=ACM")
	if opts.Path != "" {
		args = append(args, opts.Path)
	}

	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running git diff: %w", err)
	}

	return parseDiff(string(out))
}

func scanDirectory(dir string) ([]types.DiffFile, error) {
	var files []types.DiffFile

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".go", ".py", ".js", ".ts", ".tsx", ".jsx", ".rs", ".java", ".rb", ".php", ".c", ".h", ".cpp", ".hpp", ".cc":
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			files = append(files, types.DiffFile{
				Path:     path,
				Content:  string(content),
				Diff:     fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -1 +1 @@\n+file scanned", path, path),
				Language: detectLanguage(path),
			})
		}
		return nil
	})

	return files, err
}

func parseDiff(raw string) ([]types.DiffFile, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	var files []types.DiffFile
	currentFile := ""

	lines := strings.Split(raw, "\n")
	var diffLines []string

	for _, line := range lines {
		if strings.HasPrefix(line, "diff --git ") {
			if currentFile != "" {
				files = append(files, buildDiffFile(currentFile, diffLines))
			}
			parts := strings.Split(line, " b/")
			currentFile = strings.TrimPrefix(parts[len(parts)-1], "a/")
			diffLines = nil
		}
		diffLines = append(diffLines, line)
	}

	if currentFile != "" {
		files = append(files, buildDiffFile(currentFile, diffLines))
	}

	for i := range files {
		files[i].Language = detectLanguage(files[i].Path)
		content, _ := getFileContent(files[i].Path)
		files[i].Content = content
	}

	return files, nil
}

func buildDiffFile(path string, lines []string) types.DiffFile {
	return types.DiffFile{
		Path:     path,
		Diff:     strings.Join(lines, "\n"),
		Language: detectLanguage(path),
	}
}

func getFileContent(path string) (string, error) {
	if !hasHEAD() {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	cmd := exec.Command("git", "show", "HEAD:"+path)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func detectLanguage(path string) string {
	ext := ""
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		ext = strings.ToLower(path[idx:])
	}

	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".ts", ".tsx", ".jsx":
		return "typescript"
	case ".rs":
		return "rust"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".c", ".h":
		return "c"
	case ".cpp", ".hpp", ".cc":
		return "cpp"
	default:
		return "unknown"
	}
}
