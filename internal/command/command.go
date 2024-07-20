package command

import (
	"fmt"
	"rpc/internal/command/activate"
	"rpc/internal/command/configure"
	"rpc/internal/command/deactivate"
	"rpc/pkg/utils"

	// "rpc/internal/command/maintenance"
	// "rpc/internal/command/info"
	"github.com/spf13/cobra"
	"rpc/config"
)

var (
	// Root command with common flags
	RootCmd = &cobra.Command{
		Use:   "rpc",
		Short: "Remote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT",
	}

	// Global flags
	verbose    bool
	logLevel   string
	jsonOutput bool
)

func init() {
	// Add persistent flags to the root command
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	RootCmd.PersistentFlags().StringVarP(&logLevel, "logLevel", "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	RootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "JSON output")
}

func Execute(args []string, cfg *config.Config) utils.ReturnCode {
	// Add all subcommands to the root command
	// RootCmd.AddCommand(amtInfoCmd)
	RootCmd.AddCommand(activate.ActivateCmd(cfg))
	RootCmd.AddCommand(deactivate.DeactivateCmd(cfg))
	RootCmd.AddCommand(configure.ConfigureCmd(cfg))

	// Execute the root command
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
	}

	return utils.Success
}
