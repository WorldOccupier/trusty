package main

import (
	"fmt"

	"github.com/WorldOccupier/trusty/internal/upgrade"
	"github.com/spf13/cobra"
)

func init() {
	v := version
	if v == "" {
		v = upgrade.CurrentVersion()
	}
	root.Version = v
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Long:  "Print the current Trusty version.",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Println("Trusty v" + root.Version)
			return nil
		},
	}
	root.AddCommand(versionCmd)
}
