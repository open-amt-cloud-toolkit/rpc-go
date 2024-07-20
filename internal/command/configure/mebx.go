package configure

import (
	"rpc/config"
	"rpc/pkg/utils"

	"github.com/spf13/cobra"
	
)

func SetMEBxPasswordCmd(cfg *config.Config) *cobra.Command {
	var setMEBxPasswordCmd = &cobra.Command{
		Use:   utils.SubCommandSetMEBx,
		Short: "Configure the MEBx password. The MEBx password can only be configured if the device is activated in ACM mode.",
		Example: "rpc configure mebx --mebxpassword <NewMEBxPassword> --password <AMTPassword>",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMEBxPasswordUpdate(cmd, args, cfg)
		},
	}

	setMEBxPasswordCmd.Flags().StringVar(&cfg.Configure.MEBxPassword, "mebxpassword", "", "Sets MEBx password")

	return setMEBxPasswordCmd

}

func runMEBxPasswordUpdate(_ *cobra.Command, _ []string, cfg *config.Config) error {
	if cfg.Configure.AMTPassword == "" {
		password, err := PromptForPassword()
		if err != nil {
			return err
		}
		cfg.Configure.AMTPassword = password
	}

	if cfg.Configure.MEBxPassword == "" {
		password, err := PromptForPassword()
		if err != nil {
			return err
		}
		cfg.Configure.MEBxPassword = password
	}

	cfg.Configure.Subcommand = utils.SubCommandSetMEBx

	return nil
}
