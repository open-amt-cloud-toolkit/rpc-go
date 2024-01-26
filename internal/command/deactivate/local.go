package deactivate

import (
	"errors"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var deactivateLocalCmd = &cobra.Command{
	Use:   "deactivate",
	Short: "Deactivate AMT device via Local Provisioning",
	RunE:  runLocalDeactivate,
}

func init() {

	// Add the "deactivateLocal" to the deactivate command
	DeactivateCmd.AddCommand(deactivateLocalCmd)

	deactivateLocalCmd.Flags().StringP("amtPassword", "p", "", "AMT Password")
}

func runLocalDeactivate(cmd *cobra.Command, args []string) error {
	amtPassword, _ := cmd.Flags().GetString("amtPassword")
	// If password is missing, prompt the user to enter it
	if amtPassword == "" {
		log.Info("Enter AMT Password: ")
		amtPassword = viper.GetString("amtPassword")
		if amtPassword == "" {
			log.Info("AMT password not provided")
			return errors.New("AMT password not provided")
		}
	}
	return nil
}
