package maintenance

import (

	"github.com/spf13/cobra"
)

// Define the maintenanceCmd and its corresponding run function
var MaintenanceCmd = &cobra.Command{
	Use:   "maintenance",
	Short: "Perform maintenance operations on AMT using Remote Provisioning Server (RPS)",
}

func init() {
	// Add persistent flags to the root command
	MaintenanceCmd.PersistentFlags().StringVarP(&amtPassword, "amtPassword", "p", "", "AMT password (required)")
	MaintenanceCmd.PersistentFlags().StringP("url", "u", "", "Websocket address of RPS")

	// Mark "password" flag as required
	MaintenanceCmd.MarkFlagRequired("amtPassword")
}
