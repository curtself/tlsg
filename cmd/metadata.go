package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"tlsg/internal/certsvc"
	"tlsg/internal/options"
)

var (
	// metadataOpts is the package-level options holder for the metadata verb.
	metadataOpts options.MetadataOptions
)

var metadataCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Generate metadata file for a certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := metadataOpts.Validate(); err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		svc := certsvc.New()
		outputLogs, err := svc.Metadata(metadataOpts)
		if err != nil {
			return fmt.Errorf("Error generating metadata: %w", err)
		}
		for _, line := range outputLogs {
			fmt.Println(line)
		}
		return nil
	},
}

func init() {
	metadataCmd.Flags().StringArrayVarP(&metadataOpts.Certificates, "cert", "c", []string{}, "Certificate file")
	metadataCmd.Flags().StringVarP(&metadataOpts.OutputFile, "output", "o", "", "Output file path")
	metadataCmd.Flags().StringVarP(&metadataOpts.Password, "password", "p", "", "Password (optional), used with pkcs12/pfx files")
	metadataCmd.Flags().BoolVarP(&metadataOpts.Verbose, "verbose", "v", false, "Verbose output")
	rootCmd.AddCommand(metadataCmd)
}
