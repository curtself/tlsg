/*
Copyright © 2025 Curt Self <curtself.cs@gmail.com>
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"ssl-tools/internal/certsvc"
	"ssl-tools/internal/options"
)

var finishOpts options.FinishOptions

// finishCmd represents the finish command
var finishCmd = &cobra.Command{
	Use:   "finish",
	Short: "Finish a CSR request using a CSR and key file",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Running finish verb...")
		if err := finishOpts.Validate(); err != nil {
			return err
		}
		//fmt.Printf("Arguments given %+v\n",finishOpts)
		svc := certsvc.New()
		result, err := svc.FinishCSR(finishOpts)
		if err != nil {
			return fmt.Errorf("PFX creation failed: %w", err)
		}
		if finishOpts.PfxFile != "" {
			result.FileName = finishOpts.PfxFile
		}
		//fmt.Printf("Returned the PFXdto as %+v\n", result)
		outputLogs, err := svc.SavePFXdto(result)
		if err != nil {
			return err
		}
		for _, line := range outputLogs {
			fmt.Printf("%s\n", line)
		}
		return nil
	},
}

func init() {
	finishCmd.Flags().StringVarP(&finishOpts.Certificate, "certificate", "c", "", "Certificate file path (required)")
	finishCmd.Flags().StringVarP(&finishOpts.Key, "key", "k", "", "Key file path (required)")
	finishCmd.Flags().StringVarP(&finishOpts.PfxFile, "pfx", "p", "", "Pfx file path (optional)")
	finishCmd.Flags().StringVar(&finishOpts.Password, "password", "", "Password for PFX file (required)")
	finishCmd.Flags().BoolVar(&finishOpts.Chain, "chain", false, "Include the certificate chain (optional)")
	finishCmd.Flags().BoolVar(&finishOpts.IncludeRoot, "include-root", false, "Include the root certificate(s) in the chain (optional)")
	finishCmd.Flags().BoolVarP(&finishOpts.Verbose, "verbose", "v", false, "Verbose output")
	finishCmd.MarkFlagRequired("certificate")
	finishCmd.MarkFlagRequired("key")
	// password is checked via the Validate() function. It can come from cli or environment variable
	// additionally, the flag --include-root can only be enabled if --chain is enabled
	rootCmd.AddCommand(finishCmd)

}
