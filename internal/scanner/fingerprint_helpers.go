package scanner

import (
	"fmt"
	"strings"
	"unicode"
)
func isComment(line, lang string) bool {
	if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "#") {
		return true
	}
	return false
}

func isFunctionDecl(line, lang string) bool {
	switch lang {
	case "go":
		return strings.HasPrefix(line, "func ") || strings.HasPrefix(line, "func (")
	case "python":
		return strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "async def ")
	case "javascript":
		return strings.HasPrefix(line, "function ") || strings.HasPrefix(line, "const ") || strings.HasPrefix(line, "let ") || strings.HasPrefix(line, "var ")
	case "java":
		return (strings.HasPrefix(line, "public ") || strings.HasPrefix(line, "private ") || strings.HasPrefix(line, "protected ")) &&
			(strings.Contains(line, "(") && (strings.Contains(line, "{") || strings.Contains(line, ";")))
	default:
		return strings.HasPrefix(line, "func ") || strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "function ")
	}
}

func isSnakeCase(name string) bool {
	for _, r := range name {
		if unicode.IsUpper(r) {
			return false
		}
	}
	return strings.Contains(name, "_")
}

func isCamelCase(name string) bool {
	hasLower := false
	hasUpper := false
	for _, r := range name {
		if unicode.IsLower(r) {
			hasLower = true
		}
		if unicode.IsUpper(r) {
			hasUpper = true
		}
	}
	return hasLower && hasUpper && !strings.Contains(name, "_")
}

func isImportStart(line, lang string) bool {
	switch lang {
	case "go":
		return line == "import (" || line == "import"
	case "python":
		return strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "from ")
	case "javascript":
		return strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "const ") && strings.Contains(line, "require(")
	case "java":
		return strings.HasPrefix(line, "import ") && strings.Contains(line, ";")
	default:
		return false
	}
}

func isImportEnd(line, lang string) bool {
	return line == ")" || lang == "java"
}

func extractImportPath(line, lang string) string {
	switch lang {
	case "go":
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "\"") || strings.HasPrefix(line, "	\"") {
			line = strings.TrimLeft(line, " \t")
			if idx := strings.LastIndex(line, "\""); idx > 0 {
				return line[1:idx]
			}
		}
	case "python":
		if strings.HasPrefix(line, "import ") {
			return strings.TrimPrefix(line, "import ")
		}
		if strings.HasPrefix(line, "from ") {
			parts := strings.Split(line, " ")
			if len(parts) > 1 {
				return parts[1]
			}
		}
	case "javascript":
		if strings.Contains(line, "from ") {
			parts := strings.Split(line, "from ")
			if len(parts) > 1 {
				return strings.Trim(strings.TrimSpace(parts[1]), "'\"")
			}
		}
	case "java":
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "import ")
		line = strings.TrimSuffix(line, ";")
		return strings.TrimSpace(line)
	}
	return ""
}

func isStdLibImport(imp, lang string) bool {
	switch lang {
	case "go":
		return !strings.Contains(imp, ".")
	case "python":
		stdLibs := map[string]bool{"os": true, "sys": true, "json": true, "re": true, "math": true, "time": true, "pathlib": true, "collections": true, "functools": true, "itertools": true, "typing": true, "abc": true, "dataclasses": true, "enum": true, "hashlib": true, "hmac": true, "uuid": true, "datetime": true, "random": true}
		return stdLibs[strings.Split(imp, ".")[0]]
	case "java":
		return strings.HasPrefix(imp, "java.") || strings.HasPrefix(imp, "javax.") || strings.HasPrefix(imp, "jakarta.")
	default:
		return false
	}
}

func isErrorHandling(line, lang string) bool {
	lower := strings.ToLower(line)
	switch lang {
	case "go":
		return strings.Contains(lower, "if err") || strings.Contains(lower, "if err != nil") || strings.Contains(lower, "if err == nil") || strings.Contains(lower, "err != nil") || strings.Contains(lower, "return err") || strings.Contains(lower, "return fmt.errorf") || strings.Contains(lower, "errors.new(")
	case "python":
		return strings.Contains(lower, "try:") || strings.Contains(lower, "except ") || strings.Contains(lower, "raise ") || strings.Contains(lower, "finally:") || strings.Contains(lower, "valueerror") || strings.Contains(lower, "typeerror") || strings.Contains(lower, "keyerror")
	case "javascript":
		return strings.Contains(lower, "try ") || strings.Contains(lower, "catch(") || strings.Contains(lower, "catch (") || strings.Contains(lower, "throw ") || strings.Contains(lower, ".catch(") || strings.Contains(lower, "reject(")
	case "java":
		return strings.Contains(lower, "try ") || strings.Contains(lower, "catch(") || strings.Contains(lower, "catch (") || strings.Contains(lower, "throws ") || strings.Contains(lower, "throw new ") || strings.Contains(lower, "finally ") || strings.Contains(lower, "exception")
	}
	return false
}

func formatFloat(f float64) string {
	return strings.TrimRight(strings.TrimRight(
		strings.Replace(
			strings.Replace(
				fmt.Sprintf("%.4f", f), "0000", "", -1),
			"000", "", -1),
		"0"), ".")
}
