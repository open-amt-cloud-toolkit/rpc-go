package flags

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"rpc/internal/config"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"

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
	usage = usage + "  enablewifiport  Enables WiFi port and local profile synchronization settings in AMT. AMT password is required.\n"
	usage = usage + "                 Example: " + executable + " configure enablewifiport -password YourAMTPassword\n"
	usage = usage + "\nRun '" + executable + " configure COMMAND -h' for more information on a command.\n"
	fmt.Println(usage)
	return usage
}

func (f *Flags) handleConfigureCommand() utils.ReturnCode {
	if len(f.commandLineArgs) == 2 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	var rc = utils.Success

	f.SubCommand = f.commandLineArgs[2]
	switch f.SubCommand {
	case "addwifisettings":
		rc = f.handleAddWifiSettings()
	case "enablewifiport":
		rc = f.handleEnableWifiPort()
	default:
		f.printConfigurationUsage()
		rc = utils.IncorrectCommandLineParameters
	}
	if rc != utils.Success {
		return rc
	}

	f.Local = true
	if f.Password == "" {
		if f.LocalConfig.Password != "" {
			f.Password = f.LocalConfig.Password
		} else {
			if _, rc = f.ReadPasswordFromUser(); rc != utils.Success {
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

func (f *Flags) handleEnableWifiPort() utils.ReturnCode {
	var err error
	// var rc utils.ReturnCode
	if len(f.commandLineArgs) > 5 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	f.flagSetEnableWifiPort.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetEnableWifiPort.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetEnableWifiPort.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetEnableWifiPort.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")

	if err = f.flagSetEnableWifiPort.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	return utils.Success
}

func (f *Flags) handleAddWifiSettings() utils.ReturnCode {
	var err error
	var rc utils.ReturnCode
	var secretsFilePath string
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
	f.flagSetAddWifiSettings.StringVar(&f.configContent, "config", "", "specify a config file or smb: file share URL")
	f.flagSetAddWifiSettings.StringVar(&configJson, "configJson", "", "configuration as a JSON string")
	f.flagSetAddWifiSettings.StringVar(&secretsFilePath, "secrets", "", "specify a secrets file ")
	// Params for entering a single wifi config from command line
	wifiCfg := config.WifiConfig{}
	ieee8021xCfg := config.Ieee8021xConfig{}
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.ProfileName, "profileName", "", "specify wifi profile name name")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.AuthenticationMethod, "authenticationMethod", 0, "specify authentication method")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.EncryptionMethod, "encryptionMethod", 0, "specify encryption method")
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.SSID, "ssid", "", "specify ssid")
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.PskPassphrase, "pskPassphrase", f.lookupEnvOrString("PSK_PASSPHRASE", ""), "specify psk passphrase")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.Priority, "priority", 0, "specify priority")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.Username, "username", "", "specify username")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.Password, "ieee8021xPassword", f.lookupEnvOrString("IEE8021X_PASSWORD", ""), "8021x password if authenticationProtocol is PEAPv0/EAP-MSCHAPv2(2)")
	f.flagSetAddWifiSettings.IntVar(&ieee8021xCfg.AuthenticationProtocol, "authenticationProtocol", 0, "specify authentication protocol")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.ClientCert, "clientCert", "", "specify client certificate")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.CACert, "caCert", "", "specify CA certificate")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.PrivateKey, "privateKey", f.lookupEnvOrString("IEE8021X_PRIVATE_KEY", ""), "specify private key")

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
	rc = f.handleLocalConfig()
	if rc != utils.Success {
		return rc
	}
	if configJson != "" {
		err := json.Unmarshal([]byte(configJson), &f.LocalConfig)
		if err != nil {
			log.Error(err)
			return utils.IncorrectCommandLineParameters
		}
	}

	if len(f.LocalConfig.WifiConfigs) == 0 {
		log.Error("missing wifi configuration")
		return utils.MissingOrInvalidConfiguration
	}

	if secretsFilePath != "" {
		err = cleanenv.ReadConfig(secretsFilePath, &wifiSecretConfig)
		if err != nil {
			log.Error("error reading secrets file: ", err)
			return utils.FailedReadingConfiguration
		}
	}

	// merge secrets with configs
	rc = f.mergeWifiSecrets(wifiSecretConfig)
	if rc != utils.Success {
		return rc
	}

	// prompt for missing secrets
	rc = f.promptForSecrets()
	if rc != utils.Success {
		return rc
	}
	// verify configs
	rc = f.verifyWifiConfigurations()
	if rc != utils.Success {
		return rc
	}
	return utils.Success
}

func (f *Flags) mergeWifiSecrets(wifiSecretConfig config.SecretConfig) utils.ReturnCode {
	for _, secret := range wifiSecretConfig.Secrets {
		if secret.ProfileName == "" {
			continue
		}
		if secret.PskPassphrase != "" {
			for i := range f.LocalConfig.WifiConfigs {
				item := &f.LocalConfig.WifiConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.PskPassphrase = secret.PskPassphrase
				}
			}
		}
		if secret.Password != "" {
			for i := range f.LocalConfig.Ieee8021xConfigs {
				item := &f.LocalConfig.Ieee8021xConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.Password = secret.Password
				}
			}
		}
		if secret.PrivateKey != "" {
			for i := range f.LocalConfig.Ieee8021xConfigs {
				item := &f.LocalConfig.Ieee8021xConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.PrivateKey = secret.PrivateKey
				}
			}
		}
	}
	return utils.Success
}

func (f *Flags) promptForSecrets() utils.ReturnCode {
	for i := range f.LocalConfig.WifiConfigs {
		item := &f.LocalConfig.WifiConfigs[i]
		if item.ProfileName == "" {
			continue
		}
		authMethod := models.AuthenticationMethod(item.AuthenticationMethod)
		if (authMethod == models.AuthenticationMethod_WPA_PSK || authMethod == models.AuthenticationMethod_WPA2_PSK) &&
			item.PskPassphrase == "" {
			rc := f.PromptUserInput("Please enter PskPassphrase for "+item.ProfileName+": ", &item.PskPassphrase)
			if rc != utils.Success {
				return rc
			}
		}
	}
	for i := range f.LocalConfig.Ieee8021xConfigs {
		item := &f.LocalConfig.Ieee8021xConfigs[i]
		if item.ProfileName == "" {
			continue
		}
		authProtocol := models.AuthenticationProtocol(item.AuthenticationProtocol)
		if authProtocol == models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2 && item.Password == "" {
			rc := f.PromptUserInput("Please enter password for "+item.ProfileName+": ", &item.Password)
			if rc != utils.Success {
				return rc
			}
		}
		if authProtocol == models.AuthenticationProtocolEAPTLS && item.PrivateKey == "" {
			rc := f.PromptUserInput("Please enter private key for "+item.ProfileName+": ", &item.PrivateKey)
			if rc != utils.Success {
				return rc
			}
		}
	}
	return utils.Success
}

func (f *Flags) verifyWifiConfigurations() utils.ReturnCode {
	priorities := make(map[int]bool)
	for _, cfg := range f.LocalConfig.WifiConfigs {
		//Check profile name is not empty
		if cfg.ProfileName == "" {
			log.Error("missing profile name")
			return utils.MissingOrInvalidConfiguration
		}
		//Check ssid is not empty
		if cfg.SSID == "" {
			log.Error("missing ssid for config: ", cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		//Check priority is not empty
		if cfg.Priority <= 0 {
			log.Error("invalid priority for config: ", cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		//Check priority is unique
		if priorities[cfg.Priority] {
			log.Error("priority was specified previously: ", cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		priorities[cfg.Priority] = true

		authenticationMethod := models.AuthenticationMethod(cfg.AuthenticationMethod)
		switch authenticationMethod {
		case models.AuthenticationMethod_WPA_PSK:
			fallthrough
		case models.AuthenticationMethod_WPA2_PSK:
			if cfg.PskPassphrase == "" {
				log.Error("missing PskPassphrase for config: ", cfg.ProfileName)
				return utils.MissingOrInvalidConfiguration
			}
			break
		case models.AuthenticationMethod_WPA_IEEE8021x:
			fallthrough
		case models.AuthenticationMethod_WPA2_IEEE8021x:
			if cfg.ProfileName == "" {
				log.Error("missing ieee8021x profile name")
				return utils.MissingOrInvalidConfiguration
			}
			if cfg.PskPassphrase != "" {
				log.Errorf("wifi configuration for 8021x contains passphrase: %s", cfg.ProfileName)
				return utils.MissingOrInvalidConfiguration
			}
			rc := f.verifyMatchingIeee8021xConfig(cfg.Ieee8021xProfileName)
			if rc != utils.Success {
				return rc
			}
			break
		case models.AuthenticationMethod_Other:
			log.Errorf("unsupported AuthenticationMethod_Other (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case models.AuthenticationMethod_OpenSystem:
			log.Errorf("unsupported AuthenticationMethod_OpenSystem (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case models.AuthenticationMethod_SharedKey:
			log.Errorf("unsupported AuthenticationMethod_SharedKey (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case models.AuthenticationMethod_DMTFReserved:
			log.Errorf("unsupported AuthenticationMethod_DMTFReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case models.AuthenticationMethod_WPA3_SAE:
			log.Errorf("unsupported AuthenticationMethod_WPA3_SAE (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case models.AuthenticationMethod_WPA3_OWE:
			log.Errorf("unsupported AuthenticationMethod_WPA3_OWE (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case models.AuthenticationMethod_VendorReserved:
			log.Errorf("unsupported AuthenticationMethod_VendorReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		default:
			log.Errorf("invalid AuthenticationMethod_VendorReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}

		encryptionMethod := models.EncryptionMethod(cfg.EncryptionMethod)
		// NOTE: this is only
		switch encryptionMethod {
		case models.EncryptionMethod_TKIP:
			fallthrough
		case models.EncryptionMethod_CCMP:
			break
		case models.EncryptionMethod_Other:
			log.Errorf("unsupported EncryptionMethod_Other (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case models.EncryptionMethod_WEP:
			log.Errorf("unsupported EncryptionMethod_WEP (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case models.EncryptionMethod_None:
			log.Errorf("unsupported EncryptionMethod_None (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case models.EncryptionMethod_DMTFReserved:
			log.Errorf("unsupported EncryptionMethod_DMTFReserved (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		default:
			log.Errorf("invalid EncryptionMethod (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
	}
	return utils.Success
}

func (f *Flags) verifyMatchingIeee8021xConfig(profileName string) utils.ReturnCode {
	foundOne := false
	for _, ieee802xCfg := range f.LocalConfig.Ieee8021xConfigs {
		if profileName != ieee802xCfg.ProfileName {
			continue
		}
		if foundOne {
			log.Error("duplicate IEEE802x Profile names: ", ieee802xCfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		foundOne = true
		rc := f.verifyIeee8021xConfig(ieee802xCfg)
		if rc != utils.Success {
			return rc
		}
	}
	if !foundOne {
		log.Error("missing IEEE802x Profile: ", profileName)
		return utils.MissingOrInvalidConfiguration
	}
	return utils.Success
}

func (f *Flags) verifyIeee8021xConfig(cfg config.Ieee8021xConfig) utils.ReturnCode {

	if cfg.Username == "" {
		log.Error("missing username for config: ", cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	}
	if cfg.CACert == "" {
		log.Error("missing caCert for config: ", cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	}
	authenticationProtocol := models.AuthenticationProtocol(cfg.AuthenticationProtocol)
	// not all defined protocols are supported
	switch authenticationProtocol {
	case models.AuthenticationProtocolEAPTLS:
		if cfg.ClientCert == "" {
			log.Error("missing clientCert for config: ", cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		if cfg.PrivateKey == "" {
			log.Error("missing privateKey for config: ", cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		break
	case models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2:
		if cfg.Password == "" {
			log.Error("missing password for for PEAPv0_EAPMSCHAPv2 config: ", cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		break
	case models.AuthenticationProtocolEAPTTLS_MSCHAPv2:
		log.Errorf("unsupported AuthenticationProtocolEAPTTLS_MSCHAPv2 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	case models.AuthenticationProtocolPEAPv1_EAPGTC:
		log.Errorf("unsupported AuthenticationProtocolPEAPv1_EAPGTC (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	case models.AuthenticationProtocolEAPFAST_MSCHAPv2:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_MSCHAPv2 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	case models.AuthenticationProtocolEAPFAST_GTC:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_GTC (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	case models.AuthenticationProtocolEAP_MD5:
		log.Errorf("unsupported AuthenticationProtocolEAP_MD5 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	case models.AuthenticationProtocolEAP_PSK:
		log.Errorf("unsupported AuthenticationProtocolEAP_PSK (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	case models.AuthenticationProtocolEAP_SIM:
		log.Errorf("unsupported AuthenticationProtocolEAP_SIM (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	case models.AuthenticationProtocolEAP_AKA:
		log.Errorf("unsupported AuthenticationProtocolEAP_AKA (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	case models.AuthenticationProtocolEAPFAST_TLS:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_TLS (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	default:
		log.Errorf("invalid AuthenticationProtocol (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return utils.MissingOrInvalidConfiguration
	}

	return utils.Success
}
