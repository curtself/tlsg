/*
Copyright © 2025 Curt Self <curtself.cs@gmail.com>
*/
package cmd

import (
	"errors"
	"fmt"
	"github.com/spf13/cobra"
)

// autofixCmd represents the autofix command
var autofixCmd = &cobra.Command{
	Use:   "autofix",
	Short: "Automatically fixes the order of a certificate chain, and other small issues.",
	Long: `This action has not been implemented due to the constraints of the Go language
when dealing with certificates and system trust.

A version of 'autofix' that gets close to the C# application is in progress.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("autofix called")
		return errors.New("not implemented")
	},
}

func init() {
	rootCmd.AddCommand(autofixCmd)
}
