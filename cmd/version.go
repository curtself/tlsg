/*
Copyright © 2026 Curt Self <curtself.cs@gmail.com>
*/
package cmd

import (
	"fmt"
	"runtime"

	"tlsg/internal/version"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version information",
	Long:  "Display the version and build information for tlsg.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("tlsg %s\n", version.Version)
		fmt.Printf("Commit:     %s\n", version.Commit)
		fmt.Printf("Built:      %s\n", version.BuildDate)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("Platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
