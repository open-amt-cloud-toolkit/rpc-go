package configure

import (
	"rpc/config"
	"rpc/pkg/utils"

	"github.com/spf13/cobra"
	
)

func EnableWiFiPortCmd(cfg *config.Config) *cobra.Command {
	var enableWiFiPortCmd = &cobra.Command{
		Use:   utils.SubCommandEnableWifiPort,
		Short:   "Enable WiFi port and synchronize local profiles with AMT.",
        Long:    "This command enables the WiFi port on the device and synchronizes the local wireless profiles " +
                 "with the AMT configuration. This ensures that the AMT settings reflect the current OS wireless settings.",
        Example: "rpc configure enablewifiport --password <AMTPassword>",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runToEnableWiFiPort(cmd, args, cfg)
		},
	}
	
	return enableWiFiPortCmd

}

func runToEnableWiFiPort(_ *cobra.Command, _ []string, cfg *config.Config) error {
	if cfg.Configure.AMTPassword == "" {
		password, err := PromptForPassword()
		if err != nil {
			return err
		}
		cfg.Configure.AMTPassword = password
	}

	cfg.Configure.Subcommand = utils.SubCommandEnableWifiPort

	return nil
}
