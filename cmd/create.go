/*
Copyright © 2025 Curt Self <curtself.cs@gmail.com>
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"tlsg/internal/certsvc"
	"tlsg/internal/options"
)

var createOpts options.CreateOptions

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a CSR and private key",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Running create verb...")
		if err := createOpts.Validate(); err != nil {
			return err
		}
		fmt.Printf("Arguments given %+v\n", createOpts)
		svc := certsvc.New()
		if createOpts.KeySize != 0 {
			if err := svc.SetKeyLength(createOpts.KeySize); err != nil {
				return fmt.Errorf("invalid key size: %w", err)
			}
		}

		result, err := svc.CreateCSR(createOpts)
		if err != nil {
			return fmt.Errorf("CSR creation failed: %w", err)
		}
		//fmt.Printf("Returned the CSRdto as %+v\n", result)

		// Save the files
		outputLogs, err := svc.SaveCSRdto(result)
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
	createCmd.Flags().StringVarP(&createOpts.CommonName, "cn", "c", "", "Common name (required)")
	createCmd.Flags().StringArrayVarP(&createOpts.SANs, "san", "s", []string{}, "Subject Alternative Names (optional)")
	createCmd.Flags().IntVarP(&createOpts.KeySize, "keysize", "b", 0, "Key size in bits (optional)")
	createCmd.Flags().StringVarP(&createOpts.Key, "key", "k", "", "External key file path (optional)")

	createCmd.MarkFlagRequired("cn")
	rootCmd.AddCommand(createCmd)
}
