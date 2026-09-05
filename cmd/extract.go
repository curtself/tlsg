package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"tlsg/internal/certsvc"
	"tlsg/internal/options"
)

var (
	// extractOpts is the package-level options holder for the extract verb.
	extractOpts options.ExtractOptions
)

// extractCmd represents the extract command.
var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract a number of certificates starting from a given file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := extractOpts.Validate(); err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		svc := certsvc.New()
		outputLogs, err := svc.Extract(extractOpts)
		if err != nil {
			return fmt.Errorf("Error extracting certificates: %w", err)
		}
		for _, line := range outputLogs {
			fmt.Println(line)
		}
		return nil
	},
}

func init() {
	//extractCmd.Flags().StringVarP(&extractOpts.CertFile, "certificate", "c", "", "Certificate file path (required)")
	extractCmd.Flags().StringArrayVarP(&extractOpts.Certificates, "cert", "c", []string{}, "Certificate file")
	extractCmd.Flags().StringVarP(&extractOpts.OutputFile, "output", "o", "", "Output file path (optional)")
	extractCmd.Flags().IntVarP(&extractOpts.NumExtract, "number", "n", 0, "Number of certificates to extract (optional)")
	extractCmd.Flags().IntVarP(&extractOpts.SkipCount, "skip", "s", 0, "Number of certificates to skip (optional)")
	extractCmd.Flags().StringVarP(&extractOpts.Password, "password", "p", "", "Password (optional), used with pkcs12/pfx files)")
	rootCmd.AddCommand(extractCmd)
}
