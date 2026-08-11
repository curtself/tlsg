/*
Copyright © 2025 Curt Self <curtself.cs@gmail.com>
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"ssl-tools/internal/certsvc"
	"ssl-tools/internal/options"
	"strings"
)

var (
	infoOpts     options.InfoOptions
	rawHostPairs []string
)

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Gets information about certificates and CSRs",
	RunE: func(cmd *cobra.Command, args []string) error {
		// check host options
		infoOpts.Hosts = make(map[string]string)
		for _, pair := range rawHostPairs {
			parts := strings.Split(pair, "=")
			if len(parts) != 2 {
				return fmt.Errorf("Invalid host format: %s (expected host=address)", pair)
			}
			fmt.Printf("Adding host:addr of %s:%s\n", parts[0], parts[1])
			infoOpts.Hosts[parts[0]] = parts[1]
		}
		if err := infoOpts.Validate(); err != nil {
			return fmt.Errorf("Validation error: %w", err)
		}
		//fmt.Printf("Arguments given %+v\n",infoOpts)
		svc := certsvc.New()
		outputLogs, err := svc.GetInfo(infoOpts)
		if err != nil {
			return fmt.Errorf("Error getting info: %w", err)
		}
		for _, line := range outputLogs {
			fmt.Println(line)
		}
		return nil
	},
}

func init() {
	infoCmd.Flags().StringArrayVarP(&infoOpts.Certificates, "cert", "c", []string{}, "Certificate file list (optional)")
	infoCmd.Flags().StringArrayVarP(&infoOpts.URLs, "url", "u", []string{}, "URL list (optional)")
	infoCmd.Flags().StringArrayVar(&rawHostPairs, "host", []string{}, "Host mappings in the form name=address")
	infoCmd.Flags().StringVarP(&infoOpts.CSR, "csr", "r", "", "CSR file (optional)")
	infoCmd.Flags().StringVarP(&infoOpts.Password, "password", "p", "", "Password (optional, used with pkcs12/pfx files)")
	infoCmd.Flags().BoolVarP(&infoOpts.ShortSummary, "short-summary", "s", false, "Show short summary (optional)")
	rootCmd.AddCommand(infoCmd)

}
