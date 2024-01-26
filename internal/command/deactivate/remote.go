package deactivate

import (
	"errors"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var deactivateRemoteCmd = &cobra.Command{
	Use:   "deactivate",
	Short: "Deactivate AMT device in CCM/ACM",
}

func init() {
	
	// Add the "deactivateRemote" to the deactivate command
	DeactivateCmd.AddCommand(deactivateRemoteCmd)

	deactivateRemoteCmd.Flags().StringP("url", "u", "", "Websocket address of server to activate against")
	deactivateRemoteCmd.Flags().BoolP("force", "f", false, "Force the operation")
	deactivateRemoteCmd.Flags().StringP("amtPassword", "p", "", "AMT Password")
}

func runRemoteDeactivate(cmd *cobra.Command, args []string) error {
	url, err := cmd.Flags().GetString("url")
	if err != nil || url == "" {
		log.Info("url is required")
		return errors.New("url is required")
	}
	// TODO: Need to compare with existing
	amtPassword, err := cmd.Flags().GetString("amtPassword")
	if err != nil || amtPassword == "" {
		log.Info("AMT password is required")
		return errors.New("AMT password is required")
	}
	return nil
}
