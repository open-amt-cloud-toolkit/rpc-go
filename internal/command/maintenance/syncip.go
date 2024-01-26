package maintenance

import (
	"errors"
	"fmt"
	"net"
	"rpc/config"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var ipConfig config.IPConfiguration

func validateAndAssignIP(ipStr string, ipField *string, fieldName string) error {
	if net.ParseIP(ipStr) == nil {
		return errors.New("not a valid " + fieldName)
	}
	*ipField = ipStr
	return nil
}

var syncipCmd = &cobra.Command{
	Use:   "syncip",
	Short: "Sync the IP configuration of the host OS to AMT Network Settings",
	Example: "For assigning static IP address to AMT: \n" +
	         "rpc maintenance syncip -u wss://<RPS server address>/activate --amtPassword <AMT password> --staticip 192.168.1.7 --netmask 255.255.255.0 --gateway 192.168.1.1 --primarydns 8.8.8.8 --secondarydns 4.4.4.4 \n\n" +
			 "To sync host IP address to AMT: \n" +
			 "rpc maintenance syncip  -u wss://<RPS server address>/activate --amtPassword <AMT password>\n\n",
	RunE:  runSyncIP,
}

func init() {

	// Add the "syncip" subcommand to the "maintenance" command
	MaintenanceCmd.AddCommand(syncipCmd)

	// Add flags to syncipCmd
	syncipCmd.Flags().StringVar(&ipConfig.IPAddress, "staticip", "", "Assigns AMT the IP address of the active OS network interface if not specified")
	syncipCmd.Flags().StringVar(&ipConfig.Netmask, "netmask", "", "Assigns AMT the network mask of the active OS network interface if not specified")
	syncipCmd.Flags().StringVar(&ipConfig.Gateway, "gateway", "", "Gateway address to be assigned to AMT")
	syncipCmd.Flags().StringVar(&ipConfig.PrimaryDNS, "primarydns", "", "Primary DNS to be assigned to AMT")
	syncipCmd.Flags().StringVar(&ipConfig.SecondaryDNS, "secondarydns", "", "Secondary DNS to be assigned to AMT")
}

func runSyncIP(cmd *cobra.Command, args []string) error {
	// Check if static IP, netmask, gateway, primary DNS, and secondary DNS are provided
	staticIP, _ := cmd.Flags().GetString("static")
	netmask, _ := cmd.Flags().GetString("netmask")
	gateway, _ := cmd.Flags().GetString("gateway")
	primaryDNS, _ := cmd.Flags().GetString("primarydns")
	secondaryDNS, _ := cmd.Flags().GetString("secondarydns")
	amtPassword, _ := cmd.Flags().GetString("amtPassword")

	// TO DO: Check if it is ACM or not. Not sure if this is right location to check that
	// If password is missing, prompt the user to enter it
	if amtPassword == "" {
		log.Info("Enter AMT Password: ")
		// TO DO: use viper to read password
		_, err := fmt.Scan(&amtPassword) 
		if err != nil {
			return err
		}
	}

	if staticIP != "" && netmask != "" && gateway != "" && primaryDNS != "" && secondaryDNS != "" {
		ipConfig := config.IPConfiguration{} // Initialize your IPConfig struct

		if err := validateAndAssignIP(staticIP, &ipConfig.IPAddress, "static IP address"); err != nil {
			return err
		}

		if err := validateAndAssignIP(netmask, &ipConfig.Netmask, "netmask"); err != nil {
			return err
		}

		if err := validateAndAssignIP(gateway, &ipConfig.Gateway, "gateway"); err != nil {
			return err
		}

		if err := validateAndAssignIP(primaryDNS, &ipConfig.PrimaryDNS, "primaryDNS"); err != nil {
			return err
		}

		if err := validateAndAssignIP(secondaryDNS, &ipConfig.SecondaryDNS, "secondaryDNS"); err != nil {
			return err
		}

		return nil
	} else {
		log.Info("Missing IP configuration. Detecting the active OS network interface...")
	}
	return nil
}
