package maintenance

import (
	"errors"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)


var synchostnameCmd = &cobra.Command{
	Use:   "synchostname",
	Short: "Sync the hostname of the client to AMT",
	Example: "rpc maintenance synchostname -u wss://<RPS server address>/activate --amtPassword <AMT password>",
	RunE: runSyncHostname,
}

func init() {
	// Add the "synchostnameCmd" subcommand to the "maintenance" command
	MaintenanceCmd.AddCommand(synchostnameCmd)
}

func runSyncHostname(cmd *cobra.Command, args []string) error {
	amtPassword, _ := cmd.Flags().GetString("amtPassword")

	// TO DO: Check if it is ACM or not. Not sure if this is right location to check that
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