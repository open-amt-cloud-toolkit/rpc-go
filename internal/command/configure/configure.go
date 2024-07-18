package configure

import (
	"rpc/config"
	"rpc/pkg/utils"

	"github.com/spf13/cobra"
)

var validConfigs = []string{
	utils.SubCommandAddEthernetSettings,
	utils.SubCommandAddWifiSettings,
	utils.SubCommandEnableWifiPort,
	utils.SubCommandSetMEBx,
	utils.SubCommandConfigureTLS,
	utils.SubCommandSyncClock,
	utils.SubCommandChangeAMTPassword,
	utils.SubCommandSetAMTFeatures,
}

func ConfigureCmd(cfg *config.Config) *cobra.Command {
	configureCmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure AMT settings",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: validConfigs,
	}

	configureCmd.PersistentFlags().StringVar(&cfg.AMTConfiguration.AMTPassword, "amtPassword", "", "AMT Password (required to deactivate from ACM mode)")
	
	// Mark flags as mandatory
	configureCmd.MarkFlagRequired("amtPassword")

	configureCmd.AddCommand(AMTFeaturesCmd(cfg))

    return configureCmd
}