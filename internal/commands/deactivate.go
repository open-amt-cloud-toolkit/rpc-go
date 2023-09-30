package commands

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func createDeactivateCommand() *cobra.Command {
	cmdDeactivate := &cobra.Command{
		Use:   "deactivate",
		Short: "Deactivate AMT device in CCM/ACM",
	}

	// Deactivate -> Remote sub-command
	cmdRemote := &cobra.Command{
		Use:   "remote",
		Short: "Deactivate via Remote Provisioning Server (RPS).",
		RunE: func(cmd *cobra.Command, args []string) error {
			url, err := cmd.Flags().GetString("url")
			if err != nil || url == "" {
				return errors.New("url is required")
			}
			amtPassword, err := cmd.Flags().GetString("amtPassword")
			if err != nil || amtPassword == "" {
				return errors.New("AMT password is required")
			}
			return nil
		},
	}

	// Add flags to cmdRemote
	cmdRemote.Flags().StringP("url", "u", "", "Websocket address of server to activate against")
	cmdRemote.Flags().BoolP("force", "f", false, "Force the operation")
	cmdRemote.Flags().StringP("amtPassword", "p", "", "AMT Password")

	// Activate -> Local sub-command
	cmdLocal := &cobra.Command{
		Use:   "local",
		Short: "Deactivate via Remote Provisioning Client (RPC)",
		RunE: func(cmd *cobra.Command, args []string) error {
			amtPassword, _ := cmd.Flags().GetString("amtPassword")
			// TO DO: Check if it is ACM or not. Not sure if this is right location to check that
			// If password is missing, prompt the user to enter it
			if amtPassword == "" {
				fmt.Print("Enter AMT Password: ")
				_, err := fmt.Scan(&amtPassword)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmdLocal.Flags().StringP("amtPassword", "p", "", "AMT Password")

	// Add persistent flags to the root command
	cmdDeactivate.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

	// Attach the sub-commands
	cmdDeactivate.AddCommand(cmdRemote, cmdLocal)

	return cmdDeactivate
}
