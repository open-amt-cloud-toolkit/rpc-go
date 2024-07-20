package activate

import (
	"rpc/config"
	
	"github.com/spf13/cobra"
)

func ActivateCmd(cfg *config.Config) *cobra.Command {
    activateCmd := &cobra.Command{
        Use:   "activate",
        Short: "Activate AMT device",
    }

    // Pass the configuration to the activateRemoteCmd
    activateCmd.AddCommand(ActivateRemoteCmd(cfg))
	activateCmd.AddCommand(ActivateLocalCmd(cfg))

    return activateCmd
}