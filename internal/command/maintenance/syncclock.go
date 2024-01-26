package maintenance

import (
	"errors"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var syncclockCmd = &cobra.Command{
	Use:   "syncclock",
	Short: "Sync the host OS clock to AMT",
	Example: "maintenance syncclock -u wss://<RPS server address>/activate --amtPassword <AMT password>",
	RunE: runSyncClock,
}

func init() {
	// Add the "syncclockCmd" subcommand to the "maintenance" command
	MaintenanceCmd.AddCommand(syncclockCmd)
}

// runChangePassword is the run function for the syncclockCmd subcommand
func runSyncClock(cmd *cobra.Command, args []string) error {
	
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
