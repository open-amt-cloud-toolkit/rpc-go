package commands

import (
	"errors"
	"fmt"
	"rpc/internal/config"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func createConfigureCommand() *cobra.Command {
	configureCmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure addwifisettings settings",
	}

	// Create the addwifisettings sub-command
	addWifiSettingsCmd := &cobra.Command{
		Use:   "addwifisettings",
		Short: "Modify WiFi settings using an AMT password. AMT supports up to 8 profiles at a time. \n This command deletes existing profiles and adds the provided one. \n You can provide configuration as a file, JSON string, or YAML string, or use flags for a single profile.",
		RunE:  runAddWifiSettings,
	}

	// Add flags addwifisettings command
	addWifiSettingsCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
	addWifiSettingsCmd.Flags().StringP("log-level", "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	addWifiSettingsCmd.Flags().BoolP("jsonOutput", "", false, "JSON output")
	addWifiSettingsCmd.Flags().StringP("amtPassword", "", "", "AMT password")
	addWifiSettingsCmd.Flags().StringP("config", "", "", "Provide a configuration file path")
	addWifiSettingsCmd.Flags().StringP("configJSON", "", "", "Configuration as a JSON string")
	addWifiSettingsCmd.Flags().StringP("configYAML", "", "", "Configuration as a YAML string")
	// addWifiSettingsCmd.Flags().StringP(&secretsFilePath, "secrets", "", "specify a secrets file ")

	wifiCfg := config.WifiConfig{}
	ieee8021xCfg := config.Ieee8021xConfig{}

	addWifiSettingsCmd.Flags().StringVarP(&wifiCfg.ProfileName, "profileName", "", "", "Name for WiFi profile")
	addWifiSettingsCmd.Flags().IntVarP(&wifiCfg.AuthenticationMethod, "authenticationMethod", "", 0, "Accepts only 6 (WPA2 PSK) or 7 (WPA2 IEEE 802.1x)")
	addWifiSettingsCmd.Flags().IntVarP(&wifiCfg.EncryptionMethod, "encryptionMethod", "", 0, "Accepts only 3 (TKIP) or 4 (CCMP)")
	addWifiSettingsCmd.Flags().StringVarP(&wifiCfg.SSID, "ssid", "", "", "A name which identifies a wireless network")
	addWifiSettingsCmd.Flags().StringVarP(&wifiCfg.PskPassphrase, "pskPassphrase", "", "", "Accepts 8-63 characters. Required for authenticationMethod 6")
	addWifiSettingsCmd.Flags().IntVarP(&wifiCfg.Priority, "priority", "", 0, "Indicates the priority of the profile among all WiFi profiles")

	addWifiSettingsCmd.Flags().StringVarP(&wifiCfg.Ieee8021xProfileName, "ieee8021xProfileName", "", "", "A name for IEEE 802.1x profile. Required for authenticationMethod 7")
	addWifiSettingsCmd.Flags().StringVarP(&ieee8021xCfg.Username, "username", "", "", "User requesting access to the network.Accepts max 128 characters")
	addWifiSettingsCmd.Flags().StringVarP(&ieee8021xCfg.Password, "ieee8021xPassword", "", "", "A password associated with the username. Accepts max 256 length. Required for PEAPv0/EAP-MSCHAPv2")
	addWifiSettingsCmd.Flags().IntVarP(&ieee8021xCfg.AuthenticationProtocol, "authenticationProtocol", "", 0, "Accepts only 0 (EAP-TLS) or 2 (PEAPv0/EAP-MSCHAPv2)")
	addWifiSettingsCmd.Flags().StringVarP(&ieee8021xCfg.ClientCert, "clientCert", "", "", "Required for EAP-TLS")
	addWifiSettingsCmd.Flags().StringVarP(&ieee8021xCfg.CACert, "caCert", "", "", "Required for both EAP-TLS and PEAPv0/EAP-MSCHAPv2")
	addWifiSettingsCmd.Flags().StringVarP(&ieee8021xCfg.PrivateKey, "privateKey", "", "", "Required for EAP-TLS")

	// Mark flags as required for specific subcommands
	configureCmd.MarkFlagRequired("amtPassword")

	configureCmd.AddCommand(addWifiSettingsCmd)

	return configureCmd
}

func runAddWifiSettings(cmd *cobra.Command, args []string) error {
	var config AppConfig
	configPathOrString, _ := cmd.Flags().GetString("config")
	configJSONString, _ := cmd.Flags().GetString("configJSON")
	configYAMLString, _ := cmd.Flags().GetString("configYAML")
	amtPassword, _ := cmd.Flags().GetString("amtPassword")
	profileName, _ := cmd.Flags().GetString("profileName")
	authenticationMethod, _ := cmd.Flags().GetInt("authenticationMethod")
	encryptionMethod, _ := cmd.Flags().GetInt("encryptionMethod")
	ssid, _ := cmd.Flags().GetString("ssid")
	priority, _ := cmd.Flags().GetInt("priority")
	pskPassphrase, _ := cmd.Flags().GetString("pskPassphrase")
	ieee8021xProfileName, _ := cmd.Flags().GetString("ieee8021xProfileName")

	if amtPassword == "" {
		return errors.New("amtPassword is required")
	}

	if configPathOrString == "" && configJSONString == "" && configYAMLString == "" {
		if profileName == "" || authenticationMethod == 0 || encryptionMethod == 0 || ssid == "" || priority == 0 || (pskPassphrase == "" && ieee8021xProfileName == "") {
			return errors.New("At least one source (config file, config JSON, config YAML, or command flags) is required. If not, all required fields (profile name, authentication method, etc.) must be provided.")
		}
	}

	if configPathOrString != "" {
		if err := readWiFiConfigFile(configPathOrString, &config); err != nil {
			return err
		}
	} else if configJSONString != "" {
		viper.SetConfigType("json")
		if err := readWiFiSettings(configJSONString, &config); err != nil {
			return err
		}
	} else if configYAMLString != "" {
		viper.SetConfigType("yaml")
		if err := readWiFiSettings(configYAMLString, &config); err != nil {
			return err
		}
	} else {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		authenticationProtocol, _ := cmd.Flags().GetInt("authenticationProtocol")
		clientCert, _ := cmd.Flags().GetString("clientCert")
		caCert, _ := cmd.Flags().GetString("caCert")
		privateKey, _ := cmd.Flags().GetString("privateKey")

		if encryptionMethod != 3 && encryptionMethod != 4 {
			return errors.New("EncryptionMethod must be 3 (TKIP) or 4 (CCMP).")
		}

		if authenticationMethod == 6 && pskPassphrase == "" {
			return errors.New("pskPassphrase is required for authentication method 6 (WPA2 PSK)")
		}

		if authenticationMethod == 7 && (ieee8021xProfileName == "" || username == "" || authenticationProtocol < 0 || caCert == "") {
			return errors.New("For WPA2 IEEE 802.1x (7) authentication, you need ieee8021xProfileName, username, authenticationProtocol, caCert, and either clientCert/privateKey for EAP-TLS or MSCHAPv2 password.")
		}

		if authenticationMethod == 7 {
			switch {
			case authenticationProtocol == 0:
				if username == "" || clientCert == "" || caCert == "" || privateKey == "" {
					return errors.New("If AuthenticationProtocol is 0, clientCert, and privateKey are required.")
				}
			case authenticationProtocol == 2:
				if caCert == "" || password == "" {
					return errors.New("If AuthenticationProtocol is 2, password are required.")
				}
			default:
				return errors.New("AuthenticationProtocol accepts only 0 (EAP-TLS) or 2 (PEAPv0/EAP-MSCHAPv2)")
			}
		}
		// Create a new WifiSettings element
		wifiCfg := struct {
			ProfileName          string `mapstructure:"profileName"`
			SSID                 string `mapstructure:"ssid"`
			Priority             int    `mapstructure:"priority"`
			AuthenticationMethod int    `mapstructure:"authenticationMethod"`
			EncryptionMethod     int    `mapstructure:"encryptionMethod"`
			PSKPassphrase        string `mapstructure:"pskPassphrase"`
			Ieee8021xProfileName string `mapstructure:"ieee8021xProfileName"`
		}{
			ProfileName:          profileName,
			SSID:                 ssid,
			Priority:             priority,
			AuthenticationMethod: authenticationMethod,
			EncryptionMethod:     encryptionMethod,
			PSKPassphrase:        pskPassphrase,
			Ieee8021xProfileName: ieee8021xProfileName,
		}

		// Append the new WifiConfigs element to the WifiConfigs slice
		config.WifiConfigs = append(config.WifiConfigs, wifiCfg)

		ieee8021xCfg := struct {
			ProfileName            string `mapstructure:"profileName"`
			Username               string `mapstructure:"username"`
			AuthenticationProtocol int    `mapstructure:"authenticationProtocol"`
			ClientCert             string `mapstructure:"clientCert"`
			CaCert                 string `mapstructure:"caCert"`
			PrivateKey             string `mapstructure:"privateKey"`
			Password               string `mapstructure:"password"`
		}{
			ProfileName:            ieee8021xProfileName,
			Username:               username,
			AuthenticationProtocol: authenticationProtocol,
			ClientCert:             clientCert,
			CaCert:                 caCert,
			PrivateKey:             privateKey,
			Password:               password,
		}
		config.Ieee8021xConfigs = append(config.Ieee8021xConfigs, ieee8021xCfg)
	}

	fmt.Println(config) // You can use the config here

	return nil // No errors, operation successful
}

func readWiFiSettings(configString string, config *AppConfig) error {
	if err := viper.ReadConfig(strings.NewReader(configString)); err != nil {
		return err
	}
	if err := viper.Unmarshal(config); err != nil {
		return err
	}
	return nil
}

func readWiFiConfigFile(configPathOrString string, config *AppConfig) error {
	viper.SetConfigFile(configPathOrString)
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	if err := viper.Unmarshal(&config); err != nil {
		return err
	}
	return nil
}
