package configure

import (
	"os"
	"rpc/config"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
		Use:       "configure",
		Short:     "Configure AMT settings",
		Args:      cobra.OnlyValidArgs,
		ValidArgs: validConfigs,
	}

	configureCmd.PersistentFlags().StringVar(&cfg.Configure.AMTPassword, "amtpassword", "", "AMT Password (required to configure AMT)")

	configureCmd.AddCommand(AMTFeaturesCmd(cfg))
	configureCmd.AddCommand(SetMEBxPasswordCmd(cfg))
	configureCmd.AddCommand(SetAMTPasswordCmd(cfg))
	configureCmd.AddCommand(EnableWiFiPortCmd(cfg))
	configureCmd.AddCommand(SynchronizeTimeCmd(cfg))
	configureCmd.AddCommand(ConfigureTLSCmd(cfg))

	cfg.IsLocal = true
	cfg.Command = utils.CommandConfigure

	return configureCmd
}

func PromptForPassword() (password string, err error) {
	log.Infoln("Please enter AMT Password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Infoln("Error reading password:", err)
		return "", utils.MissingOrIncorrectPassword
	}
	password = string(bytePassword)
	if password == "" {
		log.Error("Missing or incorrect password")
		return "", utils.MissingOrIncorrectPassword
	}
	return password, nil
}
