package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// CfgFile represents the config file location
	CfgFile string
	// Verbose represents if the application should be verbose
	Verbose bool
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVar(&CfgFile, "config", "./config.yaml", "config file (default is ./config.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
}
