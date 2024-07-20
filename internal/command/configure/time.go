package configure

import (
	"rpc/config"
	"rpc/pkg/utils"

	"github.com/spf13/cobra"
	
)

func SynchronizeTimeCmd(cfg *config.Config) *cobra.Command {
	var synchronizeTimeCmd = &cobra.Command{
		Use:   utils.SubCommandSyncClock,
		Short: "Syncs the host OS clock to AMT.",
		Example: "rpc configure syncclock --password <AMTPassword>",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runToSynchronizeTime(cmd, args, cfg)
		},
	}

	return synchronizeTimeCmd

}

func runToSynchronizeTime(_ *cobra.Command, _ []string, cfg *config.Config) error {
	if cfg.Configure.AMTPassword == "" {
		password, err := PromptForPassword()
		if err != nil {
			return err
		}
		cfg.Configure.AMTPassword = password
	}

	cfg.Configure.Subcommand = utils.SubCommandSyncClock

	return nil
}
