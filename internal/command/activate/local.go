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

func ActivateLocalCmd(cfg *config.Config) *cobra.Command {
    
	var activateLocalCmd = &cobra.Command{
        Use:     "local",
        Short:   "Activate locally using Remote Provisioning Client (RPC)",
		Example: "rpc maintenance changepassword -u wss://<RPS server address>/activate --static <new AMT password> --amtPassword <AMT password>",
        RunE:    func(cmd *cobra.Command, args []string) error {
            return runLocalActivate(cmd, args, cfg)
        },
    }
	// Add flags specific to each activateRemote
	activateLocalCmd.Flags().BoolP("ccm", "", false, "Activate in CCM mode")
	activateLocalCmd.Flags().BoolP("acm", "", false, "Activate in ACM mode")
	activateLocalCmd.Flags().StringP("config", "", "", "Path to the configuration file or JSON/YAML string (required for ACM mode if no -amtPassword and -provisioningCert and -provisioningCertPwd are provided)")
	activateLocalCmd.Flags().StringP("configJSON", "", "", "Configuration as a JSON string")
	activateLocalCmd.Flags().StringP("configYAML", "", "", "Configuration as a YAML string")
	activateLocalCmd.Flags().StringP("amtPassword", "", "", "AMT Password (required for CCM and ACM mode or if no -config is provided)")
	activateLocalCmd.Flags().StringP("provisioningCert", "", "", "Provisioning Certificate (required for ACM mode or if no -config is provided)")
	activateLocalCmd.Flags().StringP("provisioningCertPwd", "", "", "Provisioning Certificate Password (required for CCM mode or if no -config is provided)")
	activateLocalCmd.Flags().BoolP("nocertverification", "n", false, "Disable certificate verification")

	// Mark flags as mandatory
	activateLocalCmd.MarkFlagRequired("url")
	activateLocalCmd.MarkFlagRequired("profile")

    return activateLocalCmd
}

func getFlagsFromCommand(cmd *cobra.Command, cfg *config.Config) error {
	// Map to hold string flags and their associated destinations
	stringFlags := map[string]*string{
		"config":             &cfg.ActivationProfile.ConfigPathOrString,
		"configJSON":         &cfg.ActivationProfile.ConfigJSONString,
		"configYAML":         &cfg.ActivationProfile.ConfigYAMLString,
		"amtPassword":        &cfg.ActivationProfile.AMTPassword,
		"provisioningCert":   &cfg.ActivationProfile.ProvisioningCert,
		"provisioningCertPwd": &cfg.ActivationProfile.ProvisioningCertPwd,
	}

	// Retrieve string flags
	for flag, dest := range stringFlags {
		val, err := cmd.Flags().GetString(flag)
		if err != nil {
			return err
		}
		*dest = val
	}

	// Retrieve boolean flags
	boolFlags := map[string]*bool{
		"ccm":               &cfg.ActivationProfile.CCMMode,
		"acm":               &cfg.ActivationProfile.ACMMode,
		"nocertverification": &cfg.ActivationProfile.NoCertverification,
	}
	for flag, dest := range boolFlags {
		val, err := cmd.Flags().GetBool(flag)
		if err != nil {
			return err
		}
		*dest = val
	}

	return nil
}

func runLocalActivate(cmd *cobra.Command, args []string, cfg *config.Config) error {
	err := getFlagsFromCommand(cmd, cfg)
	if err != nil {
		return err
	}

	if cfg.ActivationProfile.CCMMode && cfg.ActivationProfile.ACMMode {
		return errors.New("You cannot activate in both CCM and ACM modes simultaneously.")
	}

	if !cfg.ActivationProfile.CCMMode && !cfg.ActivationProfile.ACMMode {
		return errors.New("Please specify a mode for activation (either --ccm or --acm).")
	}

	if cfg.ActivationProfile.CCMMode {
		return activateCCM(cfg)
	}

	if cfg.ActivationProfile.ACMMode {
		return activateACM(cfg)
	}

	return nil
}

func activateCCM(cfg *config.Config) error {
	
	// If password is missing, prompt the user to enter it
	if cfg.ActivationProfile.AMTPassword == "" {
        fmt.Println("Enter AMT Password: ")
        var password string
        fmt.Scanln(&password)  // Read input from the user
        cfg.ActivationProfile.AMTPassword = password
    }

    if cfg.ActivationProfile.AMTPassword == "" {
        return errors.New("AMT password not provided")
    }

	return nil
}

func activateACM(cfg *config.Config) error {

	switch {
	case cfg.ActivationProfile.ConfigPathOrString != "":
		return readACMSettingsConfigFile(cfg.ActivationProfile.ConfigPathOrString, &acmConfig)

	case cfg.ActivationProfile.ConfigJSONString != "":
		viper.SetConfigType("json")
		return readACMSettings(cfg.ActivationProfile.ConfigJSONString, &acmConfig)

	case cfg.ActivationProfile.ConfigYAMLString != "":
		viper.SetConfigType("yaml")
		return readACMSettings(cfg.ActivationProfile.ConfigYAMLString, &acmConfig)

	default:
		missingFields := []string{}
		if cfg.ActivationProfile.AMTPassword == "" {
			missingFields = append(missingFields, "-amtPassword")
		}
		if cfg.ActivationProfile.ProvisioningCert == "" {
			missingFields = append(missingFields, "-provisioningCert")
		}
		if cfg.ActivationProfile.ProvisioningCertPwd == "" {
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