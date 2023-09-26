package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
			return errors.New("For WPA2 PSK, EncryptionMethod must be 3 (TKIP) or 4 (CCMP).")
		}

		if authenticationMethod == 6 && pskPassphrase == "" {
			return errors.New("pskPassphrase is mandatory for authentication method 6 (WPA2 PSK)")
		}

		if authenticationMethod == 7 && (ieee8021xProfileName == "" || username == "" || authenticationProtocol == 0 || clientCert == "" || caCert == "" || privateKey == "") {
			return errors.New("If authentication Method is WPA2 IEEE 802.1x (7), ieee8021xProfileName, username, authenticationProtocol, clientCert, caCert, and privateKey are required")
		}

		if authenticationMethod == 7 && authenticationProtocol == 0 {
			if username == "" || clientCert == "" || caCert == "" || privateKey == "" {
				return errors.New("If AuthenticationProtocol is 0, UserName, ClientCert, CaCert, and PrivateKey are mandatory.")
			}
		}

		if authenticationMethod == 7 && authenticationProtocol == 2 {
			if caCert == "" || password == "" {
				return errors.New("If AuthenticationProtocol is 2, CaCert and Password are mandatory.")
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
			ProfileName           string `mapstructure:"profileName"`
			Username              string `mapstructure:"username"`
			AuthenticationProtocol int    `mapstructure:"authenticationProtocol"`
			ClientCert            string `mapstructure:"clientCert"`
			CaCert                string `mapstructure:"caCert"`
			PrivateKey            string `mapstructure:"privateKey"`
			Password              string `mapstructure:"password"`
		}{
			ProfileName:           ieee8021xProfileName,
			Username:              username,
			AuthenticationProtocol: authenticationProtocol,
			ClientCert:            clientCert,
			CaCert:                caCert,
			PrivateKey:            privateKey,
			Password:              password,
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
