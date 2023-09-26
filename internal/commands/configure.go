package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var config AppConfig

func createConfigureCommand() *cobra.Command {
	configureCmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure settings",
	}

	// Create the addwifisettings sub-command
	addWifiSettingsCmd := &cobra.Command{
		Use:   "addwifisettings",
		Short: "Add or modify WiFi settings using password and config file/string or all settings as flags.",
		RunE:  runAddWifiSettings,
	}

	configureCmd.AddCommand(addWifiSettingsCmd)

	return configureCmd
}

func runAddWifiSettings(cmd *cobra.Command, args []string) error {
	configPathOrString, _ := cmd.Flags().GetString("config")
	amtPassword, _ := cmd.Flags().GetString("amtPassword")

	if amtPassword == "" {
		return errors.New("amtPassword is required")
	}

	if configPathOrString != "" {
		// Handle case where config file is provided
		config, err := readWiFiConfig(configPathOrString)
		if err != nil {
			return err // Return the actual error
		}

		// Accessing values from wifiConfigs
		for _, wifiConfig := range config.WifiConfigs {
			fmt.Println(wifiConfig)
		}

		// if err := validateConfig(); err != nil {
		// 	return err // Return the actual error
		// }
	} else {
		authenticationMethod, _ := cmd.Flags().GetInt("authenticationMethod")
		pskPassphrase, _ := cmd.Flags().GetString("pskPassphrase")
		ieee8021xProfileName, _ := cmd.Flags().GetString("ieee8021xProfileName")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		authenticationProtocol, _ := cmd.Flags().GetInt("authenticationProtocol")
		clientCert, _ := cmd.Flags().GetString("clientCert")
		caCert, _ := cmd.Flags().GetString("caCert")
		privateKey, _ := cmd.Flags().GetString("privateKey")

		if authenticationMethod == 7 {
			if ieee8021xProfileName == "" || username == "" || authenticationProtocol == 0 || clientCert == "" || caCert == "" || privateKey == "" {
				return errors.New("If authentication Method is WPA2 IEEE 802.1x (7), ieee8021xProfileName, username, authenticationProtocol, clientCert, caCert, and privateKey are required")
			}

			if authenticationProtocol == 0 && (clientCert == "" || caCert == "" || privateKey == "") {
				return errors.New("If authenticationProtocol is 0, clientCert, caCert, and privateKey are mandatory")
			}

			if authenticationProtocol == 2 && (caCert == "" || password == "") {
				return errors.New("If authenticationProtocol is 2, caCert and password are mandatory")
			}
		}

		if authenticationMethod == 6 && pskPassphrase == "" {
			return errors.New("pskPassphrase is mandatory for authentication method WPA2 PSK (6)")
		}

		// Handle case where neither amtPassword nor config is provided
		var config AppConfig

		// Access flags using cmd.Flags() here
		cmd.Flags().StringVar(&config.WifiConfigs[0].ProfileName, "profileName", "", "specify wifi profile name name")
		cmd.Flags().IntVar(&config.WifiConfigs[0].AuthenticationMethod, "authenticationMethod", 0, "specify authentication method")
		cmd.Flags().IntVar(&config.WifiConfigs[0].EncryptionMethod, "encryptionMethod", 0, "specify encryption method")
		cmd.Flags().StringVar(&config.WifiConfigs[0].SSID, "ssid", "", "specify ssid")
		cmd.Flags().StringVar(&config.WifiConfigs[0].PSKPassphrase, "pskPassphrase", "", "specify psk passphrase")
		cmd.Flags().IntVar(&config.WifiConfigs[0].Priority, "priority", 0, "specify priority")

		cmd.Flags().StringVar(&config.Ieee8021xConfigs[0].Username, "username", "", "specify username")
		cmd.Flags().StringVar(&config.Ieee8021xConfigs[0].Password, "ieee8021xPassword", "", "8021x password if authenticationProtocol is PEAPv0/EAP-MSCHAPv2(2)")
		cmd.Flags().IntVar(&config.Ieee8021xConfigs[0].AuthenticationProtocol, "authenticationProtocol", 0, "specify authentication protocol")
		cmd.Flags().StringVar(&config.Ieee8021xConfigs[0].ClientCert, "clientCert", "", "specify client certificate")
		cmd.Flags().StringVar(&config.Ieee8021xConfigs[0].CaCert, "caCert", "", "specify CA certificate")
		cmd.Flags().StringVar(&config.Ieee8021xConfigs[0].PrivateKey, "privateKey", "", "specify private key")

	}

	return nil // No errors, operation successful
}

func readWiFiConfig(configPathOrString string) (AppConfig, error) {
	if strings.HasSuffix(configPathOrString, ".json") || strings.HasSuffix(configPathOrString, ".yaml") {
		viper.SetConfigFile(configPathOrString)
		if err := viper.ReadInConfig(); err != nil {
			return config, err
		}
	} else if strings.HasPrefix(configPathOrString, "{") || strings.HasPrefix(configPathOrString, "[") {
		viper.SetConfigType("json")
		if err := viper.ReadConfig(strings.NewReader(configPathOrString)); err != nil {
			return config, err
		}
	} else if strings.HasPrefix(configPathOrString, "wifiConfigs:") || strings.HasPrefix(configPathOrString, "ieee8021xConfigs:") {
		viper.SetConfigType("yaml")
		if err := viper.ReadConfig(strings.NewReader(configPathOrString)); err != nil {
			return config, err
		}
	} else {
		return config, errors.New("Invalid configuration format or file extension")
	}

	if err := viper.Unmarshal(&config); err != nil {
		return config, err
	}

	return config, nil
}
