package cmd

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// CfgFile represents the config file location
	CfgFile string
	// Verbose represents if the application should be verbose
	Verbose bool
)

// RootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{}

// Execute adds all child commands to the root command sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		log.Error(err)
		os.Exit(-1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&CfgFile, "config", "./config.yaml", "config file (default is ./config.yaml)")
	rootCmd.Flags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
}
