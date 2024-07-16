package deactivate

import (
	"rpc/config"

	"github.com/spf13/cobra"
)

func DeactivateCmd(cfg *config.Config) *cobra.Command {
    deactivateCmd := &cobra.Command{
		Use:   "deactivate",
		Short: "Deactivate AMT device in CCM/ACM",
	}
    // Pass the configuration to the activateRemoteCmd
    // deactivateCmd.AddCommand(ActivateRemoteCmd(cfg))
	deactivateCmd.AddCommand(DeactivateLocalCmd(cfg))

    return deactivateCmd
}

