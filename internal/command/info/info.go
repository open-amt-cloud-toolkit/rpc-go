package commands

import (
	"rpc/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var info config.AmtInfo

var amtInfoCmd = &cobra.Command{
    Use:   "amtinfo",
    Short: "Retrieve information from AMT",
    Example: "rpc amtinfo",
    RunE: runAMTInfo,
}

func runAMTInfo(cmd *cobra.Command, args []string) error {
    // Access flags using cmd.Flags() here
    amtInfoCommand := cmd.Flags()
    
    // Retrieve flag values
    if len(args) > 2 {
        info.Ver, _ = amtInfoCommand.GetBool("ver")
        info.Bld, _ = amtInfoCommand.GetBool("bld")
        info.Sku, _ = amtInfoCommand.GetBool("sku")
        info.UUID, _ = amtInfoCommand.GetBool("uuid")
        info.Mode, _ = amtInfoCommand.GetBool("mode")
        info.DNS, _ = amtInfoCommand.GetBool("dns")
        info.Cert, _ = amtInfoCommand.GetBool("cert")
        info.UserCert, _ = amtInfoCommand.GetBool("userCert")
        info.Ras, _ = amtInfoCommand.GetBool("ras")
        info.Lan, _ = amtInfoCommand.GetBool("lan")
        info.Hostname, _ = amtInfoCommand.GetBool("hostname")
        info.AMTPassword, _ = amtInfoCommand.GetString("amtPassword")
    } else {
        info.Ver = true 
        info.Bld  = true
        info.Sku  = true
        info.UUID  = true
        info.Mode  = true
        info.DNS  = true
        info.Cert  = true
        info.UserCert  = true
        info.Ras  = true
        info.Lan  = true
        info.Hostname  = true
        info.AMTPassword  = ""
    }
   return nil
}

func init() {
    // Add flags using Cobra
    amtInfoCmd.Flags().BoolVar(&info.Ver, "ver", false, "BIOS Version")
    amtInfoCmd.Flags().BoolVar(&info.Bld, "bld", false, "Build Number")
    amtInfoCmd.Flags().BoolVar(&info.Sku, "sku", false, "Product SKU")
    amtInfoCmd.Flags().BoolVar(&info.UUID, "uuid", false, "Unique Identifier")
    amtInfoCmd.Flags().BoolVar(&info.Mode, "mode", false, "Current Control Mode")
    amtInfoCmd.Flags().BoolVar(&info.DNS, "dns", false, "Domain Name Suffix")
    amtInfoCmd.Flags().BoolVar(&info.Cert, "cert", false, "System Certificate Hashes (and User Certificates if AMT password is provided)")
    amtInfoCmd.Flags().BoolVar(&info.UserCert, "userCert", false, "User Certificates only. AMT password is required")
    amtInfoCmd.Flags().BoolVar(&info.Ras, "ras", false, "Remote Access Status")
    amtInfoCmd.Flags().BoolVar(&info.Lan, "lan", false, "LAN Settings")
    amtInfoCmd.Flags().BoolVar(&info.Hostname, "hostname", false, "OS Hostname")
    amtInfoCmd.Flags().StringVarP(&info.AMTPassword, "amtPassword", "p", lookupEnvOrString("AMT_PASSWORD", ""), "AMT Password")
}

// Add this function to handle environment variable or default values
func lookupEnvOrString(key string, defaultValue string) string {
	value, exists := viper.Get(key).(string)
	if exists {
		return value
	}
	return defaultValue
}