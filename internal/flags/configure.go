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
		if f.LocalConfig.Password != "" {
			f.Password = f.LocalConfig.Password
		} else {
			if _, errCode := f.ReadPasswordFromUser(); errCode != 0 {
				return utils.MissingOrIncorrectPassword
			}
			f.LocalConfig.Password = f.Password
		}
	} else {
		if f.LocalConfig.Password == "" {
			f.LocalConfig.Password = f.Password
		} else if f.LocalConfig.Password != f.Password {
			log.Error("password does not match config file password")
			return utils.MissingOrIncorrectPassword
		}
	}
	return utils.Success
}

func (f *Flags) handleAddWifiSettings() int {
	var err error
	var resultCode int
	if len(f.commandLineArgs) == 3 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
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
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.Password, "ieee8021xPassword", "", "8021x password if authenticationProtocol is PEAPv0/EAP-MSCHAPv2(2)")
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

	if wifiCfg.ProfileName != "" {
		authMethod := models.AuthenticationMethod(wifiCfg.AuthenticationMethod)
		if authMethod == models.AuthenticationMethod_WPA_IEEE8021x ||
			authMethod == models.AuthenticationMethod_WPA2_IEEE8021x {
			// reuse profilename as configuration reference
			wifiCfg.Ieee8021xProfileName = wifiCfg.ProfileName
			ieee8021xCfg.ProfileName = wifiCfg.ProfileName
		}
	}

	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfg)
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfg)
	resultCode = f.handleLocalConfig()
	if resultCode != utils.Success {
		return resultCode
	}
	if configJson != "" {
		err := json.Unmarshal([]byte(configJson), &f.LocalConfig)
		if err != nil {
			log.Error(err)
			return utils.IncorrectCommandLineParameters
		}
	}

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
		if item.ProfileName == "" {
			continue
		}
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
		if item.ProfileName == "" {
			continue
		}
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
	for _, cfg := range f.LocalConfig.WifiConfigs {
		//Check profile name is not empty
		if cfg.ProfileName == "" {
			log.Error("missing profile name")
			return utils.MissingOrIncorrectProfile
		}
		//Check ssid is not empty
		if cfg.SSID == "" {
			log.Error("missing ssid for config: ", cfg.ProfileName)
			return utils.MissingOrIncorrectProfile
		}
		//Check priority is not empty
		if cfg.Priority <= 0 {
			log.Error("invalid priority for config: ", cfg.ProfileName)
			return utils.MissingOrIncorrectProfile
		}

		authenticationMethod := models.AuthenticationMethod(cfg.AuthenticationMethod)
		switch authenticationMethod {
		case models.AuthenticationMethod_WPA_PSK:
			break
		case models.AuthenticationMethod_WPA2_PSK:
			if cfg.PskPassphrase == "" {
				log.Error("missing PskPassphrase for config: ", cfg.ProfileName)
				return utils.MissingOrIncorrectProfile
			}
			break
		case models.AuthenticationMethod_WPA_IEEE8021x:
			fallthrough
		case models.AuthenticationMethod_WPA2_IEEE8021x:
			if cfg.PskPassphrase != "" {
				log.Error("wifi configuration contains passphrase: ", cfg.ProfileName)
				return utils.MissingOrIncorrectProfile
			}
			resultCode := f.verifyMatchingIeee8021xConfig(cfg.Ieee8021xProfileName)
			if resultCode != utils.Success {
				return resultCode
			}
			break
		default:
			log.Error("invalid AuthenticationMethod for config: ", cfg.ProfileName)
			return utils.MissingOrIncorrectProfile
		}

		encryptionMethod := models.EncryptionMethod(cfg.EncryptionMethod)
		// NOTE: this is only
		switch encryptionMethod {
		case models.EncryptionMethod_TKIP:
			fallthrough
		case models.EncryptionMethod_CCMP:
			break
		default:
			log.Error("invalid EncryptionMethod for config: ", cfg.ProfileName)
			return utils.MissingOrIncorrectProfile
		}
	}
	return utils.Success
}

func (f *Flags) verifyMatchingIeee8021xConfig(profileName string) int {
	if profileName == "" {
		log.Error("empty ieee802xCfg profile name")
		return utils.MissingOrIncorrectProfile
	}
	foundOne := false
	for _, ieee802xCfg := range f.LocalConfig.Ieee8021xConfigs {
		if profileName != ieee802xCfg.ProfileName {
			continue
		}
		if foundOne {
			log.Error("duplicate IEEE802x Profile names: ", ieee802xCfg.ProfileName)
			return utils.MissingOrIncorrectProfile
		}
		foundOne = true
		resultCode := f.verifyIeee8021xConfig(ieee802xCfg)
		if resultCode != utils.Success {
			return resultCode
		}
	}
	if !foundOne {
		log.Error("missing IEEE802x Profile: ", profileName)
		return utils.MissingOrIncorrectProfile
	}
	return utils.Success
}

func (f *Flags) verifyIeee8021xConfig(cfg config.Ieee8021xConfig) int {

	if cfg.Username == "" {
		log.Error("missing Username for Ieee8021xConfig: ", cfg.ProfileName)
		return utils.MissingOrIncorrectProfile
	}
	if cfg.ClientCert == "" {
		log.Error("missing ClientCert for Ieee8021xConfig: ", cfg.ProfileName)
		return utils.MissingOrIncorrectProfile
	}
	if cfg.CACert == "" {
		log.Error("missing CACert for Ieee8021xConfig: ", cfg.ProfileName)
		return utils.MissingOrIncorrectProfile
	}
	if cfg.PrivateKey == "" {
		log.Error("missing PrivateKey for Ieee8021xConfig: ", cfg.ProfileName)
		return utils.MissingOrIncorrectProfile
	}
	authenticationProtocol := models.AuthenticationProtocol(cfg.AuthenticationProtocol)
	// not all defined protocols are supported
	switch authenticationProtocol {
	case models.AuthenticationProtocolEAPTLS:
		break
	case models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2:
		if cfg.Password == "" {
			log.Error("missing Password for for PEAPv0_EAPMSCHAPv2 Ieee8021xConfig: ", cfg.ProfileName)
			return utils.MissingOrIncorrectPassword
		}
		break
	case models.AuthenticationProtocolEAPTTLS_MSCHAPv2:
		log.Errorf("Unsupported AuthenticationProtocolEAPTTLS_MSCHAPv2 (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	case models.AuthenticationProtocolPEAPv1_EAPGTC:
		log.Errorf("Unsupported AuthenticationProtocolPEAPv1_EAPGTC (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	case models.AuthenticationProtocolEAPFAST_MSCHAPv2:
		log.Errorf("Unsupported AuthenticationProtocolEAPFAST_MSCHAPv2 (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	case models.AuthenticationProtocolEAPFAST_GTC:
		log.Errorf("Unsupported AuthenticationProtocolEAPFAST_GTC (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	case models.AuthenticationProtocolEAP_MD5:
		log.Errorf("Unsupported AuthenticationProtocolEAP_MD5 (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	case models.AuthenticationProtocolEAP_PSK:
		log.Errorf("Unsupported AuthenticationProtocolEAP_PSK (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	case models.AuthenticationProtocolEAP_SIM:
		log.Errorf("Unsupported AuthenticationProtocolEAP_SIM (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	case models.AuthenticationProtocolEAP_AKA:
		log.Errorf("Unsupported AuthenticationProtocolEAP_AKA (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	case models.AuthenticationProtocolEAPFAST_TLS:
		log.Errorf("Unsupported AuthenticationProtocolEAPFAST_TLS (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	default:
		log.Errorf("Invalid AuthenticationProtocol (%d) for Ieee8021xConfig: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.Ieee8021xConfigurationFailed
	}

	return utils.Success
}
