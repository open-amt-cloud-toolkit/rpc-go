package deactivate

import (
	"os"
	"rpc/pkg/utils"
	"rpc/config"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func DeactivateLocalCmd(cfg *config.Config) *cobra.Command {
	var deactivateLocalCmd = &cobra.Command{
		Use:   "local",
		Short: "Deactivate AMT device via Local Provisioning",
		RunE:   func(cmd *cobra.Command, args []string) error {
            return runLocalDeactivate(cmd, args, cfg)
        },
	}
	deactivateLocalCmd.Flags().StringP("amtPassword", "", "", "AMT Password (required to deactivate from ACM mode)")

	// Mark flags as mandatory
	// deactivateLocalCmd.MarkFlagRequired("amtPassword")

	return deactivateLocalCmd

}

func runLocalDeactivate(cmd *cobra.Command, _ []string, cfg *config.Config) error {
	amtPassword, err := cmd.Flags().GetString("amtPassword")
	// If password is missing, prompt the user to enter it
	if err != nil || amtPassword == "" {
		log.Infoln("Please enter AMT Password: ")
    	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Infoln("Error reading password:", err)
			return utils.MissingOrIncorrectPassword
		}
		cfg.Deactivate.AMTPassword = string(bytePassword)
		if cfg.Deactivate.AMTPassword == "" {
			log.Error("Missing or incorrect password")
			return utils.MissingOrIncorrectPassword
		}
	} 
	
	cfg.Deactivate.AMTPassword = amtPassword
	cfg.Command = utils.CommandDeactivate 
	cfg.IsLocal = true

	return nil
}
