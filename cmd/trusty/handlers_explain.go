package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
	"github.com/spf13/cobra"
)

type ruleExplanation struct {
	Name        string
	Severity    string
	Problem     string
	Example     string
	Fix         string
}

var ruleExplanations = map[string]ruleExplanation{
	"sql-injection": {
		Name:     "SQL Injection",
		Severity: "error",
		Problem:  "User input is concatenated directly into a SQL query. An attacker can inject SQL commands by providing crafted input like `' OR '1'='1`, potentially reading, modifying, or deleting database contents.",
		Example:  `query := "SELECT * FROM users WHERE name='" + username + "'"`,
		Fix:      `Use parameterized queries: db.Query("SELECT * FROM users WHERE name=?", username)`,
	},
	"xss": {
		Name:     "Cross-Site Scripting (XSS)",
		Severity: "error",
		Problem:  "User input is written directly to HTTP responses without sanitization. Attackers can inject JavaScript that executes in other users' browsers, stealing cookies or session tokens.",
		Example:  `fmt.Fprintf(w, "<div>%s</div>", userInput)`,
		Fix:      `Use proper escaping: template.HTMLEscapeString(userInput) or html.EscapeString()`,
	},
	"command-injection": {
		Name:     "Command Injection",
		Severity: "error",
		Problem:  "User input is concatenated into a shell command. Attackers can execute arbitrary system commands by injecting shell metacharacters like `; rm -rf /` or `$(malicious)`.",
		Example:  `exec.Command("sh", "-c", "echo "+input)`,
		Fix:      `Use argument form: exec.Command("echo", input). Avoid shell invocation when possible.`,
	},
	"hardcoded-secret": {
		Name:     "Hardcoded Secret",
		Severity: "error",
		Problem:  "A credential, API key, or token is hardcoded in source code. Anyone with access to the repository can use these credentials. Committed secrets are exposed to all collaborators and leak in CI logs.",
		Example:  `apiKey := "sk-1234567890abcdef"`,
		Fix:      `Use environment variables: os.Getenv("API_KEY") or a secrets manager like HashiCorp Vault.`,
	},
	"path-traversal": {
		Name:     "Path Traversal",
		Severity: "error",
		Problem:  "User input is used in file operations without validation. Attackers can read/write files outside the intended directory using `../` sequences.",
		Example:  `os.ReadFile("/data/" + userInput)`,
		Fix:      `Use filepath.Clean() and filepath.Base() to sanitize paths, and validate against an allowlist.`,
	},
	"insecure-crypto": {
		Name:     "Insecure Cryptography",
		Severity: "error",
		Problem:  "Weak or outdated cryptographic algorithms are used. These can be broken with modern hardware, compromising encrypted data.",
		Example:  `crypto.NewDESCipher(key)`,
		Fix:      `Use AES-256-GCM or ChaCha20-Poly1305 instead of DES, RC4, or MD5.`,
	},
	"off-by-one": {
		Name:     "Off-by-One Error",
		Severity: "warning",
		Problem:  "A loop uses `<=` instead of `<`, iterating one time too many. This is a classic AI-generated code bug that causes index out of range panics or silent data corruption.",
		Example:  `for i := 0; i <= n; i++ { sum += i }  // should be i < n`,
		Fix:      `Use < instead of <= for zero-based iteration: for i := 0; i < n; i++`,
	},
	"inverted-conditional": {
		Name:     "Inverted Conditional",
		Severity: "info",
		Problem:  "A comparison direction looks suspicious (e.g., `>` where `<` would be expected). This can indicate the logic is backwards, especially in AI-generated code.",
		Example:  `if len(items) > 0 && len(items) > limit {  // may be inverted`,
		Fix:      "Verify the comparison direction matches the intended logic. Consider using bool variables for clarity.",
	},
	"self-assignment": {
		Name:     "Self-Assignment",
		Severity: "warning",
		Problem:  "A variable is assigned to itself (`x = x`). This is nearly always a bug — AI models sometimes generate tautological assignments when they can't determine the correct variable.",
		Example:  `v = v  // self-assignment — intended to be a different variable?`,
		Fix:      `Check the intended variable name. If it's a typo, fix the variable name. If it's initialization, use the zero value or a literal.`,
	},
	"shadowed-variable": {
		Name:     "Shadowed Variable",
		Severity: "warning",
		Problem:  "A local variable shadows an outer variable with the same name. This can cause confusing behavior where the outer variable is unexpectedly not modified.",
		Example:  `func foo() { x := 1; { x := 2; } // outer x is unchanged }`,
		Fix:      `Rename the inner variable or use direct assignment (= instead of :=) to modify the outer variable.`,
	},
	"nil-dereference": {
		Name:     "Nil Dereference",
		Severity: "error",
		Problem:  "A pointer, map, or channel is used without checking if it's nil. This causes a runtime panic that crashes the application.",
		Example:  `var m map[string]int; m["key"] = 1  // panic: assignment to entry in nil map`,
		Fix:      `Initialize before use: m := make(map[string]int) or check: if m != nil { ... }`,
	},
	"infinite-loop": {
		Name:     "Potential Infinite Loop",
		Severity: "warning",
		Problem:  "A loop condition may never become false. AI-generated code sometimes omits loop variable updates, creating infinite loops that hang the application.",
		Example:  `for i := 0; i < n; { /* i never incremented */ }`,
		Fix:      `Ensure the loop variable is updated each iteration: for i := 0; i < n; i++ { ... }`,
	},
	"missing-default": {
		Name:     "Missing Switch Default",
		Severity: "info",
		Problem:  "A switch statement has no default case. If no case matches, execution falls through silently, potentially leaving variables uninitialized or state inconsistent.",
		Example:  `switch status { case "ok": ... case "err": ... }  // no default`,
		Fix:      `Add a default case that handles unexpected values: default: return fmt.Errorf("unknown status: %s", status)`,
	},
	"mutable-default": {
		Name:     "Mutable Default Argument",
		Severity: "warning",
		Problem:  "A Python function uses a mutable object (list, dict) as a default argument. The default is shared across all calls, so mutations persist between invocations.",
		Example:  `def add_item(item, items=[]):  # items is shared!`,
		Fix:      `Use None as default and initialize inside: def add_item(item, items=None): if items is None: items = []`,
	},
	"unused-import": {
		Name:     "Unused Import",
		Severity: "warning",
		Problem:  "A package is imported but never used. This is a compilation error in Go. AI models often generate imports for packages they intended to use but forgot.",
		Example:  `import "fmt"  // imported but never used in the file`,
		Fix:      `Remove the unused import, or add the code that requires it.`,
	},
	"unchecked-error": {
		Name:     "Unchecked Error Return",
		Severity: "error",
		Problem:  "A function that returns an error is called but the error is discarded with `_`. This can silently hide failures like network errors, permission denials, or data corruption.",
		Example:  `db.Query(query)  // error return ignored`,
		Fix:      `Check the error: rows, err := db.Query(query); if err != nil { return fmt.Errorf("query: %w", err) }`,
	},
	"hallucinated-import": {
		Name:     "Hallucinated Import",
		Severity: "error",
		Problem:  "An import refers to a package or module that does not exist. AI language models sometimes invent package names that look plausible but don't exist in any registry.",
		Example:  `import "github.com/openai/golang-sdk"  // does not exist`,
		Fix:      `Verify the import path against the actual package registry. Check documentation or use 'go get' to test.`,
	},
}

func runExplain(_ *cobra.Command, args []string) error {
	arg := args[0]

	if strings.HasSuffix(arg, ".json") {
		data, err := os.ReadFile(arg)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}
		var result types.ScanResult
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("parsing scan result: %w", err)
		}
		return explainFindings(result)
	}

	ruleID := strings.ToLower(arg)
	exp, ok := ruleExplanations[ruleID]
	if !ok {
		return fmt.Errorf("unknown rule: %s\n\nAvailable rules: %s", ruleID, listRuleIDs())
	}

	printExplanation(ruleID, exp)
	return nil
}

func explainFindings(result types.ScanResult) error {
	found := 0
	for _, file := range result.Files {
		for _, f := range file.Findings {
			if exp, ok := ruleExplanations[f.Rule]; ok {
				if found == 0 {
					fmt.Printf("Explaining %d findings from scan result:\n\n", countFindings(result))
				}
				found++
				fmt.Printf("=== Finding %d: %s (%s) ===\n", found, exp.Name, file.Path)
				printExplanation(f.Rule, exp)
			}
		}
	}
	if found == 0 {
		fmt.Println("No recognized findings to explain.")
	}
	return nil
}

func countFindings(r types.ScanResult) int {
	n := 0
	for _, f := range r.Files {
		n += len(f.Findings)
	}
	return n
}

func printExplanation(id string, exp ruleExplanation) {
	fmt.Printf("  Rule:    %s\n", id)
	fmt.Printf("  Name:    %s\n", exp.Name)
	fmt.Printf("  Problem: %s\n", exp.Problem)
	fmt.Printf("  Example: %s\n", exp.Example)
	fmt.Printf("  Fix:     %s\n\n", exp.Fix)
}

func listRuleIDs() string {
	ids := make([]string, 0, len(ruleExplanations))
	for id := range ruleExplanations {
		ids = append(ids, id)
	}
	return strings.Join(ids, ", ")
}
