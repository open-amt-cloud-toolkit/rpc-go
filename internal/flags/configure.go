package flags

import (
	"encoding/json"
	"fmt"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"
	"os"
	"path/filepath"
	"rpc/internal/config"
	"rpc/pkg/utils"

	"github.com/ilyakaznacheev/cleanenv"
	log "github.com/sirupsen/logrus"
)

func (f *Flags) printConfigurationUsage() string {
	executable := filepath.Base(os.Args[0])
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"
	usage = usage + "Usage: " + executable + " configure COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Configuration Commands:\n"
	usage = usage + "  addwifisettings Add or modify WiFi settings in AMT. AMT password is required. A config.yml or command line flags must be provided for all settings. This command runs without cloud interaction.\n"
	usage = usage + "                 Example: " + executable + " configure addwifisettings -password YourAMTPassword -config wificonfig.yaml\n"
	usage = usage + "\nRun '" + executable + " configure COMMAND -h' for more information on a command.\n"
	fmt.Println(usage)
	return usage
}

func (f *Flags) handleConfigureCommand() int {
	if len(f.commandLineArgs) == 2 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	var resultCode = utils.Success

	f.SubCommand = f.commandLineArgs[2]
	switch f.SubCommand {
	case "addwifisettings":
		resultCode = f.handleAddWifiSettings()
		break
	default:
		f.printConfigurationUsage()
		resultCode = utils.IncorrectCommandLineParameters
		break
	}
	if resultCode != utils.Success {
		return resultCode
	}

	f.Local = true
	if f.Password == "" {
		if _, errCode := f.ReadPasswordFromUser(); errCode != 0 {
			return utils.MissingOrIncorrectPassword
		}
	}
	f.LocalConfig.Password = f.Password
	return utils.Success
}

func (f *Flags) handleAddWifiSettings() int {
	var err error
	var resultCode int
	var wifiSecretConfig config.SecretConfig
	var configJson string
	f.flagSetAddWifiSettings.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetAddWifiSettings.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetAddWifiSettings.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetAddWifiSettings.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
	f.flagSetAddWifiSettings.StringVar(&f.LocalConfig.FilePath, "configFile", "", "specify a config file ")
	f.flagSetAddWifiSettings.StringVar(&configJson, "configJson", "", "configuration as a JSON string")
	f.flagSetAddWifiSettings.StringVar(&wifiSecretConfig.FilePath, "secretFile", "", "specify a secret file ")
	// Params for entering a single wifi config from command line
	wifiCfg := config.WifiConfig{}
	ieee8021xCfg := config.Ieee8021xConfig{}
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.ProfileName, "profileName", "", "specify wifi profile name name")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.AuthenticationMethod, "authenticationMethod", 0, "specify authentication method")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.EncryptionMethod, "encryptionMethod", 0, "specify encryption method")
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.SSID, "ssid", "", "specify ssid")
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.PskPassphrase, "pskPassphrase", "", "specify psk passphrase")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.Priority, "priority", 0, "specify priority")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.Username, "username", "", "specify username")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.Password, "ieee8021xPassword", "", "specify ieee8021x password")
	f.flagSetAddWifiSettings.IntVar(&ieee8021xCfg.AuthenticationProtocol, "authenticationProtocol", 0, "specify authentication protocol")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.ClientCert, "clientCert", "", "specify client certificate")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.CACert, "caCert", "", "specify CA certificate")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.PrivateKey, "privateKey", "", "specify private key")

	// rpc configure addwifisettings -configstring "{ prop: val, prop2: val }"
	// rpc configure add -config "filename" -secrets "someotherfile"
	if err = f.flagSetAddWifiSettings.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	// port the profile name as it is understood a 8021x config will 'match' this wificfg
	if wifiCfg.ProfileName != "" {
		wifiCfg.Ieee8021xProfileName = wifiCfg.ProfileName
		// don't worry if wifiCfg is not using 8021x, it will be ignored or verified later
		ieee8021xCfg.ProfileName = wifiCfg.ProfileName
	}

	if configJson != "" {
		err := json.Unmarshal([]byte(configJson), &f.LocalConfig)
		if err != nil {
			log.Error(err)
			return utils.IncorrectCommandLineParameters
		}
	}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfg)
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfg)
	resultCode = f.handleLocalConfig()
	if resultCode != utils.Success {
		return resultCode
	}
	cfgs, err := json.Marshal(f.LocalConfig)
	if err != nil {
		log.Error("unable to marshal activationResponse to JSON")
		return 0
	}
	fmt.Println(string(cfgs))

	if wifiSecretConfig.FilePath != "" {
		err = cleanenv.ReadConfig(wifiSecretConfig.FilePath, &wifiSecretConfig)
		if err != nil {
			log.Error("error reading secrets file: ", err)
			return utils.FailedReadingConfiguration
		}
	}

	// merge secrets with configs
	resultCode = f.mergeWifiSecrets(wifiSecretConfig)
	if resultCode != utils.Success {
		return resultCode
	}
	// prompt for missing secrets
	resultCode = f.promptForSecrets()
	if resultCode != utils.Success {
		return resultCode
	}
	// verify configs
	resultCode = f.verifyWifiConfigurations()
	if resultCode != utils.Success {
		return resultCode
	}
	return utils.Success
}

func (f *Flags) mergeWifiSecrets(wifiSecretConfig config.SecretConfig) int {
	for _, secret := range wifiSecretConfig.Secrets {
		if secret.ProfileName == "" {
			continue
		}
		if secret.PskPassphrase != "" {
			for i, _ := range f.LocalConfig.WifiConfigs {
				item := &f.LocalConfig.WifiConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.PskPassphrase = secret.PskPassphrase
				}
			}
		}
		if secret.Password != "" {
			for i, _ := range f.LocalConfig.Ieee8021xConfigs {
				item := &f.LocalConfig.Ieee8021xConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.Password = secret.Password
				}
			}
		}
		if secret.PrivateKey != "" {
			for i, _ := range f.LocalConfig.Ieee8021xConfigs {
				item := &f.LocalConfig.Ieee8021xConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.PrivateKey = secret.PrivateKey
				}
			}
		}
	}
	return utils.Success
}

func (f *Flags) promptForSecrets() int {
	for i, _ := range f.LocalConfig.WifiConfigs {
		item := &f.LocalConfig.WifiConfigs[i]
		authMethod := models.AuthenticationMethod(item.AuthenticationMethod)
		if authMethod == models.AuthenticationMethod_WPA2_PSK &&
			item.PskPassphrase == "" {
			resultCode := f.PromptUserInput("Please enter PskPassphrase for "+item.ProfileName+": ", &item.PskPassphrase)
			if resultCode != utils.Success {
				return resultCode
			}
		}
	}
	for i, _ := range f.LocalConfig.Ieee8021xConfigs {
		item := &f.LocalConfig.Ieee8021xConfigs[i]
		authProtocol := models.AuthenticationProtocol(item.AuthenticationProtocol)
		if authProtocol == models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2 &&
			item.Password == "" {
			resultCode := f.PromptUserInput("Please enter password for "+item.ProfileName+": ", &item.Password)
			if resultCode != utils.Success {
				return resultCode
			}
		}
		if item.PrivateKey == "" {
			resultCode := f.PromptUserInput("Please enter private key for "+item.ProfileName+": ", &item.PrivateKey)
			if resultCode != utils.Success {
				return resultCode
			}
		}
	}
	return utils.Success
}

func (f *Flags) verifyWifiConfigurations() int {
	for _, wifiConfigs := range f.LocalConfig.WifiConfigs {
		//Check profile name is not empty
		if wifiConfigs.ProfileName == "" {
			log.Error("missing profile name")
			return utils.MissingOrIncorrectProfile
		}
		//Check ssid is not empty
		if wifiConfigs.SSID == "" {
			log.Error("missing ssid for profile: ", wifiConfigs.ProfileName)
			return utils.MissingOrIncorrectProfile
		}
		//Check priority is not empty
		if wifiConfigs.Priority == 0 {
			log.Error("missing priority for profile: ", wifiConfigs.ProfileName)
			return utils.MissingOrIncorrectProfile
		}
		//Check authenticationMethod is not empty
		if wifiConfigs.AuthenticationMethod == 0 {
			log.Error("missing authenticationMethod for profile: ", wifiConfigs.ProfileName)
			return utils.MissingOrIncorrectProfile
		}
		//Check encryptionMethod is not empty
		if wifiConfigs.EncryptionMethod == 0 {
			log.Error("missing encryptionMethod for profile: ", wifiConfigs.ProfileName)
			return utils.MissingOrIncorrectProfile
		}
		//Check authentication method
		if wifiConfigs.AuthenticationMethod == 6 && wifiConfigs.PskPassphrase == "" {
			log.Error("wifi configuration missing passphrase: ", wifiConfigs.ProfileName)
			return utils.MissingOrIncorrectProfile
		}
		if (wifiConfigs.AuthenticationMethod == 5 || wifiConfigs.AuthenticationMethod == 7) && wifiConfigs.PskPassphrase != "" {
			log.Error("wifi configuration contains passphrase: ", wifiConfigs.ProfileName)
			return utils.MissingOrIncorrectProfile
		}
		if wifiConfigs.AuthenticationMethod == 5 || wifiConfigs.AuthenticationMethod == 7 {
			//Check for ieee8021xProfileName in IEEE8021XSettings
			var matchedIeeeProfileName int = 0

			for _, ieee802xSettings := range f.LocalConfig.Ieee8021xConfigs {
				if wifiConfigs.Ieee8021xProfileName == ieee802xSettings.ProfileName {
					matchedIeeeProfileName++
				}
				// fmt.Println("ieee:", ieee802xSettings)
			}
			//Check if more than on ieee profile name matched.
			if matchedIeeeProfileName > 1 {
				log.Error("duplicate IEEE802x Profile names")
				return utils.MissingOrIncorrectProfile
			}
		}
		// fmt.Println("wifi: ", wifiConfigs)
	}
	for _, ieee8021xConfigs := range f.LocalConfig.Ieee8021xConfigs {
		//Check profile name is not empty in IEEE802.1x config
		if ieee8021xConfigs.ProfileName == "" {
			log.Error("missing profile name in IEEE802.1x config")
			return utils.MissingOrIncorrectProfile
		}
	}
	return utils.Success
}
func ieee8021xCfgIsEmpty(config config.Ieee8021xConfig) bool {
	return config.ProfileName == "" &&
		config.Username == "" &&
		config.Password == "" &&
		config.AuthenticationProtocol == 0 &&
		config.ClientCert == "" &&
		config.CACert == "" &&
		config.PrivateKey == ""
}
