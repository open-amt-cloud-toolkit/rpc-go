package maintenance

import (
	"errors"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var changepasswordCmd = &cobra.Command{
	Use:     "changepassword",
	Short:   "Change the AMT password",
	Example: "rpc maintenance changepassword -u wss://<RPS server address>/activate --static <new AMT password> --amtPassword <AMT password>",
	RunE:     runChangePassword,
}

// Flags for changepasswordCmd
var amtPassword string
var static string

func init() {
	// Add the "changepassword" subcommand to the "maintenance" command
	MaintenanceCmd.AddCommand(changepasswordCmd)

	// Add flags to changepasswordCmd
	changepasswordCmd.Flags().StringVarP(&static, "static", "s", "", "Set a new static AMT password (default is random)")
}

func runChangePassword(cmd *cobra.Command, args []string) error {
	
	newPassword, _ := cmd.Flags().GetString("static")
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
	
	// Check if a static password should be set
	if newPassword != "" {
		log.Info("Setting a static password: ", static)
	} else {
		log.Info("Generating a random password for AMT")
	}

	return nil
}
