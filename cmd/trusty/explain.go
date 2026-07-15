package main

import (
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:   "explain [rule-id or results.json]",
	Short: "Explain a finding rule or scan result in detail",
	Long: `Show detailed explanation of a Trusty finding rule, including
what it detects, why it matters, and how to fix it.

With a .json scan result file, explains all findings in the report.

Examples:
  trusty explain sql-injection
  trusty explain off-by-one
  trusty explain results.json`,
	Args: cobra.ExactArgs(1),
	RunE: runExplain,
}

func init() {
	root.AddCommand(explainCmd)
}
