package flags

import (
	"fmt"
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

	var errCode = utils.Success

	f.SubCommand = f.commandLineArgs[2]
	switch f.SubCommand {
	case "addwifisettings":
		errCode = f.handleAddWifiSettings()
		break
	default:
		f.printConfigurationUsage()
		errCode = utils.IncorrectCommandLineParameters
		break
	}
	if errCode != utils.Success {
		return errCode
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

	f.flagSetAddWifiSettings.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetAddWifiSettings.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetAddWifiSettings.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetAddWifiSettings.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
	f.flagSetAddWifiSettings.StringVar(&f.configContent, "config", "", "specify a config file ")
	// TODO: these are the params for entering a single wifi config from command line
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
	if err := f.flagSetAddWifiSettings.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfg)
	//Check if ieee8021x is empty, if so do not append.
	if !ieee8021xCfgIsEmpty(ieee8021xCfg) {
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfg)
	}

	if f.configContent != "" {
		err := cleanenv.ReadConfig(f.configContent, &f.LocalConfig)
		if err != nil {
			log.Error("config error: ", err)
			return utils.IncorrectCommandLineParameters
		}
	}

	configFileStatus := f.verifyWifiConfigurationFile()
	if configFileStatus != 0 {
		log.Error("config error")
		// log.Error("config error: ", err)
		return utils.IncorrectCommandLineParameters
	}
	return utils.Success
}

func (f *Flags) verifyWifiConfigurationFile() int {
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
