package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile         string
	outputFmt       string
	minScore        int
	minSeverity     string
	fuzzIterations  int
	from            string
	to              string
	base            string
	head            string
	staged          bool
	verbose         bool
	fuzzDir         string
	noCache         bool
	fingerprintAll  bool
	outFile         string
	diffFile        string
	trackRegression bool
	allPackages     bool
	policyFile      string
	policyURL       string

	root = &cobra.Command{
		Use:   "trusty",
		Short: "AI Code Verification CLI",
		Long: `Trusty automates verification of AI-generated code.
3-tier engine: static analysis, LLM semantic analysis, behavioral verification.

Only 29% of developers trust AI-generated code. Trusty gives teams
confidence to ship faster.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "help" || cmd.Name() == "completion" {
				return nil
			}
			if cfgFile == "" {
				for _, name := range []string{".trusty.yml", ".trusty.yaml"} {
					if _, err := os.Stat(name); err == nil {
						cfgFile = name
						break
					}
				}
			}
			return nil
		},
	}
)

func main() {
	root.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file path")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	initCommands(root)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
