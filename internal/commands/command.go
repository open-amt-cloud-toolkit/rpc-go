package commands

import (
	"fmt"
	"rpc/pkg/utils"

	"github.com/spf13/cobra"
)

func HandleCommands(args []string) utils.ReturnCode {
	// Define a root command
	var rootCmd = &cobra.Command{Use: "rpc"}

	// Create the cmdActivate command
	activateCmd := createActivateCommand()

	// Create the cmdDeactivate command
	deactivateCmd := createDeactivateCommand()

	// Create the cmdConfigure command
	configureCmd := createConfigureCommand()

	// Add either activateCmd or deactivateCmd based on user input
	if len(args) == 1 {
		fmt.Println("Please specify either 'activate' or 'deactivate' as a sub-command.")
		fmt.Println()
		rootCmd.Help() // Print root command's help and available sub-commands
		return 1
	} else if args[1] == "activate" {
		rootCmd.AddCommand(activateCmd)
	} else if args[1] == "deactivate" {
		rootCmd.AddCommand(deactivateCmd)
	} else if args[1] == "configure" {
		rootCmd.AddCommand(configureCmd)
	} else {
		fmt.Println("Invalid sub-command. Please specify either 'activate' or 'deactivate'.")
		return 1
	}

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}

	return utils.Success
}
