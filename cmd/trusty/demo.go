package main

import (
	"github.com/spf13/cobra"
)

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run a demo scan with sample AI-generated code",
	Long: `Creates a temporary project with sample Go files containing
common AI-generated code issues, then runs the full scan pipeline.
Shows what Trusty can detect without needing a real project.

Examples:
  trusty demo`,
	RunE: runDemo,
}

func init() {
	root.AddCommand(demoCmd)
}
