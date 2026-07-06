// cmd/root.go
package cmd

import (
	"github.com/spf13/cobra"
	"os"
	"ssl-tools/internal/version"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "ssl-tools",
	Short:   "Certificate and CSR helper utility",
	Version: version.Version,
	Long: `A certificate and CSR helper utility to make life easier.

This is the Go port of the original C# project by the same name.
There are some minor differences but all features should (eventually) work.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
}
