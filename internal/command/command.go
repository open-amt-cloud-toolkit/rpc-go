package command

import (
	"fmt"
	"rpc/pkg/utils"
	"rpc/internal/command/activate"
	"rpc/internal/command/deactivate"
	// "rpc/internal/command/maintenance"
	// "rpc/internal/command/info"
	"rpc/config"

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
}

func Execute(args []string, cfg *config.Config) utils.ReturnCode {
	// Add all subcommands to the root command
	// RootCmd.AddCommand(amtInfoCmd)
	RootCmd.AddCommand(activate.ActivateCmd(cfg))
	RootCmd.AddCommand(deactivate.DeactivateCmd(cfg))
	// RootCmd.AddCommand(maintenance.MaintenanceCmd)

	// Execute the root command
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
	}

	return utils.Success
}
