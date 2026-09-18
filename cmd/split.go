package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"tlsg/internal/certsvc"
	"tlsg/internal/options"
)

var (
	// splitOpts is the package-level options holder for the split command.
	splitOpts options.SplitOptions
)

// splitCmd represents the split command
var splitCmd = &cobra.Command{
	Use:   "split",
	Short: "Split a certificate chain into its component files",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := splitOpts.Validate(); err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		svc := certsvc.New()
		outputLogs, err := svc.Split(splitOpts)
		if err != nil {
			return fmt.Errorf("Error splitting certificate: %w", err)
		}
		for _, line := range outputLogs {
			fmt.Println(line)
		}
		return nil
	},
}

func init() {
	splitCmd.Flags().StringVarP(&splitOpts.Certificate, "cert", "c", "", "Certificate file")
	splitCmd.Flags().StringVarP(&splitOpts.OutputDir, "output", "o", "", "Output directory")
	splitCmd.Flags().StringVarP(&splitOpts.Password, "password", "p", "", "Password (optional), used with pkcs12/pfx files)")
	splitCmd.Flags().BoolVarP(&splitOpts.Verbose, "verbose", "v", false, "Verbose output")
	splitCmd.Flags().BoolVarP(&splitOpts.KeyExtract, "key", "k", false, "Extract a key if present")
	rootCmd.AddCommand(splitCmd)
}
