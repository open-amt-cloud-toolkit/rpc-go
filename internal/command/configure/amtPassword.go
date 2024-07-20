package configure

import (
	"rpc/config"
	"rpc/pkg/utils"

	"github.com/spf13/cobra"
	
)

func SetAMTPasswordCmd(cfg *config.Config) *cobra.Command {
	var setAMTPasswordCmd = &cobra.Command{
		Use:   utils.SubCommandChangeAMTPassword,
		Short:   "Change or update the AMT password of the device.",
		Long:    "This command changes the AMT password of the device. Please note that this command does not communicate " +
		         "with a centralized database to store the new AMT passwords. Ensure to record any changes made securely.",
		Example: "rpc configure amtpassword --newamtpassword <NewAMTPassword> --password <AMTPassword>",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAMTPasswordUpdate(cmd, args, cfg)
		},
	}

	setAMTPasswordCmd.Flags().StringVar(&cfg.Configure.NewAMTPassword, "newamtpassword", "", "Sets AMT password")

	return setAMTPasswordCmd

}

func runAMTPasswordUpdate(_ *cobra.Command, _ []string, cfg *config.Config) error {
	if cfg.Configure.AMTPassword == "" {
		amtPassword, err := PromptForPassword()
		if err != nil {
			return err
		}
		cfg.Configure.AMTPassword = amtPassword
	}

	if cfg.Configure.NewAMTPassword == "" {
		newPassword, err := PromptForPassword()
		if err != nil {
			return err
		}
		cfg.Configure.NewAMTPassword = newPassword
	}

	// cfg.IsLocal = true
	// cfg.Command = utils.CommandConfigure
	cfg.Configure.Subcommand = utils.SubCommandChangeAMTPassword

	return nil
}
