package flags

import (
	"fmt"
	"rpc/pkg/utils"

	"github.com/ilyakaznacheev/cleanenv"
	log "github.com/sirupsen/logrus"
)

func (f *Flags) handleConfigureCommand() int {
	f.amtConfigureCommand.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
	f.amtConfigureCommand.StringVar(&f.configContent, "config", "", "specify a config file ")
	if err := f.amtConfigureCommand.Parse(f.commandLineArgs[3:]); err != nil {
		f.amtConfigureCommand.Usage()
		return utils.IncorrectCommandLineParameters
	}
	//if err := f.amtConfigureAddWiFiSettingsCommand.Parse(f.commandLineArgs[2:]); err != nil {
	//	f.amtConfigureCommand.Usage()
	//	return utils.IncorrectCommandLineParameters
	//}
	// runs locally
	f.Local = true

	f.SubCommand = f.commandLineArgs[2]
	switch f.SubCommand {
	case "addwifisettings":
		if f.configContent == "" {
			fmt.Println("-config flag is required and cannot be empty")
			return utils.IncorrectCommandLineParameters
		}
		err := cleanenv.ReadConfig(f.configContent, &f.LocalConfig)
		if err != nil {
			log.Error("config error: ", err)
			return utils.IncorrectCommandLineParameters
		}
		configFileStatus := f.verifyWifiConfigurationFile()
		if configFileStatus != 0 {
			log.Error("config error: ", err)
			return utils.IncorrectCommandLineParameters
		}
	}
	return utils.Success
}

func (f *Flags) verifyWifiConfigurationFile() int {
	var matchedIeeeProfileName int = 0

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
