package activate

import (
	"errors"
	"fmt"
	"rpc/config"
	"rpc/pkg/utils"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func ActivateLocalCmd(cfg *config.Config) *cobra.Command {

	var activateLocalCmd = &cobra.Command{
		Use:     "local",
		Short:   "Activate locally using Remote Provisioning Client (RPC)",
		Example: "rpc maintenance changepassword -u wss://<RPS server address>/activate --static <new AMT password> --amtPassword <AMT password>",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLocalActivate(cmd, args, cfg)
		},
	}
	// Add flags specific to each activateRemote
	activateLocalCmd.Flags().StringVar(&cfg.Activate.Mode, "mode", "", "ccm(client control mode) or acm(admin control mode)")
	activateLocalCmd.Flags().StringVar(&cfg.Activate.ConfigPathOrString, "config", "", "Path to the configuration file or JSON/YAML string (required for ACM mode if no -amtPassword and -provisioningCert and -provisioningCertPwd are provided)")
	activateLocalCmd.Flags().StringVar(&cfg.Activate.ConfigJSONString, "configjson", "", "Configuration as a JSON string")
	activateLocalCmd.Flags().StringVar(&cfg.Activate.ConfigYAMLString, "configyaml", "", "Configuration as a YAML string")
	activateLocalCmd.Flags().StringVar(&cfg.Activate.AMTPassword, "amtpassword", "", "AMT Password (required for CCM and ACM mode or if no -config is provided)")
	activateLocalCmd.Flags().StringVar(&cfg.Activate.ProvisioningCert, "provisioningcert", "", "Provisioning Certificate (required for ACM mode or if no -config is provided)")
	activateLocalCmd.Flags().StringVar(&cfg.Activate.ProvisioningCertPwd, "provisioningcertpwd", "", "Provisioning Certificate Password (required for CCM mode or if no -config is provided)")

	return activateLocalCmd
}

func runLocalActivate(_ *cobra.Command, _ []string, cfg *config.Config) error {
	cfg.IsLocal = true
	cfg.Command = utils.CommandActivate

	if cfg.Activate.ConfigPathOrString != "" {
		return readConfigFile(cfg)
	}
	if cfg.Activate.ConfigJSONString != "" {
		return readConfig(cfg, "json")
	}
	if cfg.Activate.ConfigYAMLString != "" {
		return readConfig(cfg, "yaml")
	}

	return validateConfig(cfg)
}

func readConfigFile(config *config.Config) error {
	viper.SetConfigFile(config.Activate.ConfigPathOrString)
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	acmConfig := viper.Sub("activate")
	if acmConfig == nil {
		return errors.New("activate settings not found in config")
	}
	if err := acmConfig.Unmarshal(config); err != nil {
		return err
	}
	return validateConfig(config)
}

func readConfig(config *config.Config, configType string) error {
	var configString string
	viper.SetConfigType(configType)
	if configType == "json" {
		configString = config.Activate.ConfigJSONString
	} else if configType == "yaml" {
		configString = config.Activate.ConfigYAMLString
	}
	if err := viper.ReadConfig(strings.NewReader(configString)); err != nil {
		return err
	}
	acmConfig := viper.Sub("activate")
	if acmConfig != nil {
		if err := acmConfig.Unmarshal(config); err != nil {
			return err
		}
	}
	if err := viper.Unmarshal(config); err != nil {
		return err
	}
	return validateConfig(config)
}

func validateConfig(config *config.Config) error {
	missingFields := []string{}

	// Check if mode is provided and valid
	switch config.Activate.Mode {
	case "":
		missingFields = append(missingFields, "--mode")
	case "ccm":
		// For CCM, AMT password is required
		if config.Activate.AMTPassword == "" {
			missingFields = append(missingFields, "--amtpassword")
		}
	case "acm":
		// For ACM, AMT password, provisioning cert, and cert password are required
		if config.Activate.AMTPassword == "" {
			missingFields = append(missingFields, "--amtpassword")
		}
		if config.Activate.ProvisioningCert == "" {
			missingFields = append(missingFields, "--provisioningcert")
		}
		if config.Activate.ProvisioningCertPwd == "" {
			missingFields = append(missingFields, "--provisioningcertpwd")
		}
	default:
		return fmt.Errorf("invalid mode: %s, must be 'ccm' (client control mode) or 'acm' (admin control mode)", config.Activate.Mode)
	}

	// Report any missing fields
	if len(missingFields) > 0 {
		missingFieldsStr := strings.Join(missingFields, ", ")
		errMsg := fmt.Sprintf("Missing required flags for %s mode activation: %s", config.Activate.Mode, missingFieldsStr)
		log.Error(errMsg)
		return errors.New(errMsg)
	}

	return nil
}
