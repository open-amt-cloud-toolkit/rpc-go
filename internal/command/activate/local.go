package activate

import (
	"errors"
	"fmt"
	"rpc/config"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var acmConfig config.ACMSettings

var activateLocalCmd = &cobra.Command{
	Use:   "local",
	Short: "Activate locally using Remote Provisioning Client (RPC)",
	RunE:  runLocalActivate,
}

func init() {
	
	// Add the "activateLocal" to the activate command
	ActivateCmd.AddCommand(activateLocalCmd)

	activateLocalCmd.Flags().BoolP("ccm", "", false, "Activate in CCM mode")
	activateLocalCmd.Flags().BoolP("acm", "", false, "Activate in ACM mode")
	activateLocalCmd.Flags().StringP("config", "", "", "Path to the configuration file or JSON/YAML string (required for ACM mode if no -amtPassword and -provisioningCert and -provisioningCertPwd are provided)")
	activateLocalCmd.Flags().StringP("configJSON", "", "", "Configuration as a JSON string")
	activateLocalCmd.Flags().StringP("configYAML", "", "", "Configuration as a YAML string")
	activateLocalCmd.Flags().StringP("amtPassword", "", "", "AMT Password (required for CCM and ACM mode or if no -config is provided)")
	activateLocalCmd.Flags().StringP("provisioningCert", "", "", "Provisioning Certificate (required for ACM mode or if no -config is provided)")
	activateLocalCmd.Flags().StringP("provisioningCertPwd", "", "", "Provisioning Certificate Password (required for CCM mode or if no -config is provided)")
	activateLocalCmd.Flags().BoolP("nocertverification", "n", false, "Disable certificate verification")
}

func getFlagsFromCommand(cmd *cobra.Command) (activationFlags, error) {
	var flags activationFlags

	// Map to hold string flags and their associated destinations
	stringFlags := map[string]*string{
		"config":             &flags.configPathOrString,
		"configJSON":         &flags.configJSONString,
		"configYAML":         &flags.configYAMLString,
		"amtPassword":        &flags.amtPassword,
		"provisioningCert":   &flags.provisioningCert,
		"provisioningCertPwd": &flags.provisioningCertPwd,
	}

	// Retrieve string flags
	for flag, dest := range stringFlags {
		val, err := cmd.Flags().GetString(flag)
		if err != nil {
			return flags, err
		}
		*dest = val
	}

	// Retrieve boolean flags
	boolFlags := map[string]*bool{
		"ccm":               &flags.ccmMode,
		"acm":               &flags.acmMode,
		"nocertverification": &flags.nocertverification,
	}
	for flag, dest := range boolFlags {
		val, err := cmd.Flags().GetBool(flag)
		if err != nil {
			return flags, err
		}
		*dest = val
	}

	return flags, nil
}

func runLocalActivate(cmd *cobra.Command, args []string) error {
	flags, err := getFlagsFromCommand(cmd)
	if err != nil {
		return err
	}

	if flags.ccmMode && flags.acmMode {
		return errors.New("You cannot activate in both CCM and ACM modes simultaneously.")
	}

	if !flags.ccmMode && !flags.acmMode {
		return errors.New("Please specify a mode for activation (either --ccm or --acm).")
	}

	if flags.ccmMode {
		return activateCCM(flags)
	}

	if flags.acmMode {
		return activateACM(flags)
	}

	return nil
}

func activateCCM(flags activationFlags) error {
	
	// If password is missing, prompt the user to enter it
	if flags.amtPassword == "" {
        fmt.Println("Enter AMT Password: ")
        var password string
        fmt.Scanln(&password)  // Read input from the user
        flags.amtPassword = password
    }

    if flags.amtPassword == "" {
        return errors.New("AMT password not provided")
    }

	return nil
}

func activateACM(flags activationFlags) error {

	switch {
	case flags.configPathOrString != "":
		return readACMSettingsConfigFile(flags.configPathOrString, &acmConfig)

	case flags.configJSONString != "":
		viper.SetConfigType("json")
		return readACMSettings(flags.configJSONString, &acmConfig)

	case flags.configYAMLString != "":
		viper.SetConfigType("yaml")
		return readACMSettings(flags.configYAMLString, &acmConfig)

	default:
		missingFields := []string{}
		if flags.amtPassword == "" {
			missingFields = append(missingFields, "-amtPassword")
		}
		if flags.provisioningCert == "" {
			missingFields = append(missingFields, "-provisioningCert")
		}
		if flags.provisioningCertPwd == "" {
			missingFields = append(missingFields, "-provisioningCertPwd")
		}
	
		if len(missingFields) > 0 {
			missingFieldsStr := strings.Join(missingFields, ", ")
			errMsg := fmt.Sprintf("Missing required flags for ACM activation: %s. Alternatively, provide a configuration using -config, -configJSON, or -configYAML", missingFieldsStr)
			log.Error(errMsg)
			return errors.New(errMsg)
		}
	}

	return nil
}

func readACMSettingsConfigFile(configPathOrString string, config *config.ACMSettings) error {
	viper.SetConfigFile(configPathOrString)
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	acmConfig := viper.Sub("acmactivate")
    if acmConfig == nil {
        return errors.New("acmactivate settings not found in config")
    }
	if err := acmConfig.Unmarshal(config); err != nil {
		return err
	}
	return validateConfig(config)
}

func readACMSettings(configString string, config *config.ACMSettings) error {
	if err := viper.ReadConfig(strings.NewReader(configString)); err != nil {
		return err
	}
	if err := viper.Unmarshal(config); err != nil {
		return err
	}
	return validateConfig(config)
}

func validateConfig(config *config.ACMSettings) error {
	if acmConfig.AMTPassword == "" || acmConfig.ProvisioningCert == "" || acmConfig.ProvisioningCertPwd == "" {
		return errors.New("One or more required configurations are missing")
	}
	return nil
}