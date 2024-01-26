package commands

import (
	"fmt"
	"rpc/pkg/utils"
	"rpc/internal/command/activate"
	"rpc/internal/command/deactivate"
	"rpc/internal/command/maintenance"
	// "rpc/internal/command/info"

	"github.com/spf13/cobra"
)

type activationFlags struct {
	url                string
	profile            string
	uuid               string
	name               string
	dns                string
	hostname           string
	ccmMode            bool
	acmMode            bool
	configPathOrString string
	configJSONString   string
	configYAMLString   string
	amtPassword        string
	provisioningCert   string
	provisioningCertPwd string
	nocertverification bool
}

var (
	// Root command with common flags
	RootCmd = &cobra.Command{
		Use:   "rpc",
		Short: "Remote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT",
	}

	// Global flags
	verbose bool
)

func init() {
	// Add persistent flags to the root command
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Add all subcommands to the root command
	// RootCmd.AddCommand(amtInfoCmd)
	RootCmd.AddCommand(activate.ActivateCmd)
	RootCmd.AddCommand(deactivate.DeactivateCmd)
	RootCmd.AddCommand(maintenance.MaintenanceCmd)
}

func HandleCommands(args []string) utils.ReturnCode {
	// Execute the root command
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
	}

	return utils.Success
}
