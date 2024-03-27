/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"rpc/internal/config"
	"rpc/pkg/utils"
	"strings"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"

	"github.com/ilyakaznacheev/cleanenv"
	log "github.com/sirupsen/logrus"
)

type TLSMode int

const (
	TLSModeServer TLSMode = iota
	TLSModeServerAndNonTLS
	TLSModeMutual
	TLSModeMutualAndNonTLS
)

func (m TLSMode) String() string {
	switch m {
	case TLSModeServer:
		return "Server"
	case TLSModeServerAndNonTLS:
		return "ServerAndNonTLS"
	case TLSModeMutual:
		return "Mutual"
	case TLSModeMutualAndNonTLS:
		return "MutualAndNonTLS"
	default:
		return "Unknown"
	}
}

func TLSModesToString() string {
	return fmt.Sprintf("%s, %s, %s, %s", TLSModeServer, TLSModeServerAndNonTLS, TLSModeMutual, TLSModeMutualAndNonTLS)
}

func ParseTLSMode(s string) (TLSMode, error) {
	var m TLSMode
	var err error
	switch s {
	case "Server":
		m = TLSModeServer
	case "ServerAndNonTLS":
		m = TLSModeServerAndNonTLS
	case "Mutual":
		m = TLSModeMutual
	case "MutualAndNonTLS":
		m = TLSModeMutualAndNonTLS
	default:
		// flags error handling already shows appropriate message
		err = errors.New("")
	}
	return m, err
}

type ConfigTLSInfo struct {
	TLSMode        TLSMode
	DelayInSeconds int
	EAAddress      string
	EAUsername     string
	EAPassword     string
}

func (f *Flags) printConfigurationUsage() string {
	baseCommand := fmt.Sprintf("%s %s", filepath.Base(os.Args[0]), utils.CommandConfigure)
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"
	usage += "Usage: " + baseCommand + " COMMAND [OPTIONS]\n\n"
	usage += "Supported Configuration Commands:\n"
	usage += "  " + utils.SubCommandAddEthernetSettings + " Add or modify ethernet settings in AMT. AMT password is required. A config.yml or command line flags must be provided for all settings. This command runs without cloud interaction.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandAddEthernetSettings + " -password YourAMTPassword -config ethernetconfig.yaml\n"
	usage += "  " + utils.SubCommandAddWifiSettings + " Add or modify WiFi settings in AMT. AMT password is required. A config.yml or command line flags must be provided for all settings. This command runs without cloud interaction.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandAddWifiSettings + " -password YourAMTPassword -config wificonfig.yaml\n"
	usage += "  " + utils.SubCommandEnableWifiPort + "  Enables WiFi port and local profile synchronization settings in AMT. AMT password is required.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandEnableWifiPort + " -password YourAMTPassword\n"
	usage += "  " + utils.SubCommandConfigureTLS + "             Configures TLS in AMT. AMT password is required.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandConfigureTLS + " -mode Server -password YourAMTPassword\n"
	usage += "  " + utils.SubCommandSetMEBx + "            Configures MEBx Password. AMT password is required.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandSetMEBx + " -mebxpassword YourMEBxPassword -password YourAMTPassword\n"
	usage += "  " + utils.SubCommandSyncClock + "       Sync the host OS clock to AMT. AMT password is required\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandSyncClock + " -password YourAMTPassword\n"
	usage += "  " + utils.SubCommandSetAMTFeatures + "     Enables or Disables KVM, SOL, IDER. Sets user consent option (kvm, all, or none).\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandSetAMTFeatures + " -userConsent all -kvm -sol -ider\n"
	usage += "  " + utils.SubCommandChangeAMTPassword + "     Updates AMT password. If flags are not provided, new and current AMT passwords will be prompted for. AMT password is required\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandChangeAMTPassword + " -password YourAMTPassword -newamtpassword YourNewPassword\n"
	usage += "\nRun '" + baseCommand + " COMMAND -h' for more information on a command.\n"
	fmt.Println(usage)
	return usage
}

func (f *Flags) handleConfigureCommand() error {
	if len(f.commandLineArgs) == 2 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	var err error

	f.SubCommand = f.commandLineArgs[2]
	switch f.SubCommand {
	case utils.SubCommandAddEthernetSettings:
		err = f.handleAddEthernetSettings()
	case utils.SubCommandAddWifiSettings:
		err = f.handleAddWifiSettings()
	case utils.SubCommandEnableWifiPort:
		err = f.handleEnableWifiPort()
	case utils.SubCommandConfigureTLS:
		err = f.handleConfigureTLS()
	case utils.SubCommandSetMEBx:
		err = f.handleMEBxPassword()
	case utils.SubCommandSyncClock:
		err = f.handleSyncClock()
	case utils.SubCommandChangeAMTPassword:
		err = f.handleChangeAMTPassword()
	case utils.SubCommandSetAMTFeatures:
		err = f.handleSetAMTFeatures()
	default:
		f.printConfigurationUsage()
		err = utils.IncorrectCommandLineParameters
	}
	if err != nil {
		return err
	}

	f.Local = true
	if f.Password == "" {
		if f.LocalConfig.Password != "" {
			f.Password = f.LocalConfig.Password
		} else {
			if err = f.ReadPasswordFromUser(); err != nil {
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
	return nil
}

func (f *Flags) handleChangeAMTPassword() error {
	fs := f.NewConfigureFlagSet(utils.SubCommandChangeAMTPassword)
	fs.StringVar(&f.NewPassword, "newamtpassword", "", "New AMT password")

	if len(f.commandLineArgs) > 3 {
		if err := fs.Parse(f.commandLineArgs[3:]); err != nil {
			f.printConfigurationUsage()
			return utils.IncorrectCommandLineParameters
		}
	}

	if f.Password == "" {
		if rc := f.ReadPasswordFromUser(); rc != nil {
			return rc
		}
	}

	if f.NewPassword == "" {
		if rc := f.ReadNewPasswordTo(&f.NewPassword, "New AMT Password"); rc != nil {
			return rc
		}
	}

	return nil
}

func (f *Flags) handleSyncClock() error {
	if err := f.amtMaintenanceSyncClockCommand.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	return nil
}

func (f *Flags) handleSetAMTFeatures() error {
	var err error
	if len(f.commandLineArgs) == 3 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	f.flagSetAMTFeatures.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetAMTFeatures.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetAMTFeatures.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetAMTFeatures.StringVar(&f.UserConsent, "userConsent", "", "Sets userconsent (ACM only): kvm, all, none")
	f.flagSetAMTFeatures.BoolVar(&f.KVM, "kvm", false, "Enables or Disables KVM (Keyboard, Video, Mouse)")
	f.flagSetAMTFeatures.BoolVar(&f.SOL, "sol", false, "Enables or Disables SOL (Serial Over LAN)")
	f.flagSetAMTFeatures.BoolVar(&f.IDER, "ider", false, "Enables or Disables IDER (IDE Redirection)")
	f.flagSetAMTFeatures.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")

	if err = f.flagSetAMTFeatures.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	// Validate UserConsent
	if f.UserConsent != "" {
		f.UserConsent = strings.ToLower(f.UserConsent)
		switch f.UserConsent {
		case "kvm", "all", "none":
			return nil
		default:
			f.printConfigurationUsage()
			log.Error("invalid value for userconsent: ", f.UserConsent)
			return utils.IncorrectCommandLineParameters
		}
	}

	return nil
}

func (f *Flags) handleMEBxPassword() error {
	f.flagSetMEBx.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetMEBx.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetMEBx.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetMEBx.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
	f.flagSetMEBx.StringVar(&f.MEBxPassword, "mebxpassword", f.lookupEnvOrString("MEBX_PASSWORD", ""), "MEBX password")

	if len(f.commandLineArgs) > 3 {
		if err := f.flagSetMEBx.Parse(f.commandLineArgs[3:]); err != nil {
			f.printConfigurationUsage()
			return utils.IncorrectCommandLineParameters
		}
	}

	if f.Password == "" {
		if rc := f.ReadPasswordFromUser(); rc != nil {
			return rc
		}
	}

	if f.MEBxPassword == "" {
		if rc := f.ReadNewPasswordTo(&f.MEBxPassword, "New MEBx Password"); rc != nil {
			return rc
		}
	}

	return nil
}

func (f *Flags) handleEnableWifiPort() error {
	var err error
	// var rc error
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
	return nil
}

func (f *Flags) NewConfigureFlagSet(subCommand string) *flag.FlagSet {
	fs := flag.NewFlagSet(subCommand, flag.ContinueOnError)
	// these flags are common to all configuration commands
	fs.BoolVar(&f.Verbose, "v", false, "Verbose output")
	fs.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	fs.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	fs.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
	return fs
}

func (f *Flags) handleConfigureTLS() error {
	fs := f.NewConfigureFlagSet(utils.SubCommandConfigureTLS)
	tlsModeUsage := fmt.Sprintf("TLS authentication usage model (%s) (default %s)", TLSModesToString(), f.ConfigTLSInfo.TLSMode)
	fs.Func("mode", tlsModeUsage, func(flagValue string) error {
		var e error
		f.ConfigTLSInfo.TLSMode, e = ParseTLSMode(flagValue)
		return e
	})

	fs.IntVar(&f.ConfigTLSInfo.DelayInSeconds, "delay", 3, "Delay time in seconds after putting remote TLS settings")
	fs.StringVar(&f.ConfigTLSInfo.EAAddress, "eaAddress", "", "Enterprise Assistant address")
	fs.StringVar(&f.ConfigTLSInfo.EAUsername, "eaUsername", "", "Enterprise Assistant username")
	fs.StringVar(&f.ConfigTLSInfo.EAPassword, "eaPassword", "", "Enterprise Assistant password")

	if len(f.commandLineArgs) < (3 + 0) {
		fs.Usage()
		return utils.IncorrectCommandLineParameters
	}
	if err := fs.Parse(f.commandLineArgs[3:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}
	if len(fs.Args()) > 0 {
		fmt.Printf("unhandled additional args: %v\n", fs.Args())
		fs.Usage()
		return utils.IncorrectCommandLineParameters
	}
	return nil
}

func (f *Flags) handleAddEthernetSettings() error {
	var configJson string
	fs := f.NewConfigureFlagSet(utils.SubCommandAddEthernetSettings)
	fs.StringVar(&f.configContent, "config", "", "Specify a config file or smb: file share URL")
	fs.StringVar(&configJson, "configJson", "", "Configuration as a JSON string")
	fs.BoolVar(&f.IpConfiguration.DHCP, "dhcp", false, "Configures wired settings to use dhcp")
	fs.BoolVar(&f.IpConfiguration.Static, "static", false, "Configures wired settings to use static ip address")
	fs.BoolVar(&f.IpConfiguration.IpSync, "ipsync", false, "Sync the IP configuration of the host OS to AMT Network Settings")
	fs.Func(
		"ipaddress",
		"IP address to be assigned to AMT",
		validateIP(&f.IpConfiguration.IpAddress))
	fs.Func(
		"subnetmask",
		"Subnetwork mask to be assigned to AMT",
		validateIP(&f.IpConfiguration.Netmask))
	fs.Func("gateway", "Gateway address to be assigned to AMT", validateIP(&f.IpConfiguration.Gateway))
	fs.Func("primarydns", "Primary DNS to be assigned to AMT", validateIP(&f.IpConfiguration.PrimaryDns))
	fs.Func("secondarydns", "Secondary DNS to be assigned to AMT", validateIP(&f.IpConfiguration.SecondaryDns))

	if err := fs.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	if f.configContent != "" || configJson != "" {
		err := f.handleLocalConfig()
		if err != nil {
			return utils.FailedReadingConfiguration
		}
		if configJson != "" {
			err := json.Unmarshal([]byte(configJson), &f.LocalConfig)
			if err != nil {
				log.Error(err)
				return utils.IncorrectCommandLineParameters
			}
		}

		if f.IpConfiguration.DHCP ||
			f.IpConfiguration.Static ||
			f.IpConfiguration.IpSync ||
			f.IpConfiguration.IpAddress != "" ||
			f.IpConfiguration.Netmask != "" ||
			f.IpConfiguration.Gateway != "" ||
			f.IpConfiguration.PrimaryDns != "" ||
			f.IpConfiguration.SecondaryDns != "" {
			return utils.IncorrectCommandLineParameters
		}

		f.IpConfiguration.DHCP = f.LocalConfig.WiredConfig.DHCP
		f.IpConfiguration.Static = f.LocalConfig.WiredConfig.Static
		f.IpConfiguration.IpSync = f.LocalConfig.WiredConfig.IpSync
		f.IpConfiguration.IpAddress = f.LocalConfig.WiredConfig.IpAddress
		f.IpConfiguration.Netmask = f.LocalConfig.WiredConfig.Subnetmask
		f.IpConfiguration.Gateway = f.LocalConfig.WiredConfig.Gateway
		f.IpConfiguration.PrimaryDns = f.LocalConfig.WiredConfig.PrimaryDNS
		f.IpConfiguration.SecondaryDns = f.LocalConfig.WiredConfig.SecondaryDNS

	}

	if f.IpConfiguration.DHCP == f.IpConfiguration.Static {
		log.Error("must specify -dhcp or -static, but not both")
		return utils.InvalidParameterCombination
	}

	if f.IpConfiguration.DHCP && !f.IpConfiguration.IpSync {
		return utils.InvalidParameterCombination
	}

	if f.IpConfiguration.IpSync {
		if f.IpConfiguration.IpAddress != "" ||
			f.IpConfiguration.Netmask != "" ||
			f.IpConfiguration.Gateway != "" ||
			f.IpConfiguration.PrimaryDns != "" ||
			f.IpConfiguration.SecondaryDns != "" {
			return utils.InvalidParameterCombination
		}
	}

	if f.IpConfiguration.Static && !f.IpConfiguration.IpSync {
		if f.IpConfiguration.IpAddress == "" {
			return utils.MissingOrIncorrectStaticIP
		}
		if f.IpConfiguration.Netmask == "" {
			return utils.MissingOrIncorrectNetworkMask
		}
		if f.IpConfiguration.Gateway == "" {
			return utils.MissingOrIncorrectGateway
		}
		if f.IpConfiguration.PrimaryDns == "" {
			return utils.MissingOrIncorrectPrimaryDNS
		}
	}

	return nil
}

func (f *Flags) handleAddWifiSettings() error {
	var err error
	var secretsFilePath string
	var wifiSecretConfig config.SecretConfig
	var configJson string
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
	f.flagSetAddWifiSettings.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetAddWifiSettings.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetAddWifiSettings.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetAddWifiSettings.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")

	// rpc configure addwifisettings is not enough paramaters, need -config or a combination of command line flags
	if len(f.commandLineArgs[3:]) == 0 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	// rpc configure addwifisettings -configstring "{ prop: val, prop2: val }"
	// rpc configure add -config "filename" -secrets "someotherfile"
	if err = f.flagSetAddWifiSettings.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	if wifiCfg.ProfileName != "" {
		authMethod := wifi.AuthenticationMethod(wifiCfg.AuthenticationMethod)
		if authMethod == wifi.AuthenticationMethod_WPA_IEEE8021x ||
			authMethod == wifi.AuthenticationMethod_WPA2_IEEE8021x {
			// reuse profilename as configuration reference
			wifiCfg.Ieee8021xProfileName = wifiCfg.ProfileName
			ieee8021xCfg.ProfileName = wifiCfg.ProfileName
		}
	}

	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfg)
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfg)
	err = f.handleLocalConfig()
	if err != nil {
		return utils.FailedReadingConfiguration
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
	err = f.mergeWifiSecrets(wifiSecretConfig)
	if err != nil {
		return err
	}

	// prompt for missing secrets
	err = f.promptForSecrets()
	if err != nil {
		return err
	}
	// verify configs
	err = f.verifyWifiConfigurations()
	if err != nil {
		return err
	}
	return nil
}

func (f *Flags) mergeWifiSecrets(wifiSecretConfig config.SecretConfig) error {
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
	return nil
}

func (f *Flags) promptForSecrets() error {
	for i := range f.LocalConfig.WifiConfigs {
		item := &f.LocalConfig.WifiConfigs[i]
		if item.ProfileName == "" {
			continue
		}
		authMethod := wifi.AuthenticationMethod(item.AuthenticationMethod)
		if (authMethod == wifi.AuthenticationMethod_WPA_PSK || authMethod == wifi.AuthenticationMethod_WPA2_PSK) &&
			item.PskPassphrase == "" {
			err := f.PromptUserInput("Please enter PskPassphrase for "+item.ProfileName+": ", &item.PskPassphrase)
			if err != nil {
				return err
			}
		}
	}
	for i := range f.LocalConfig.Ieee8021xConfigs {
		item := &f.LocalConfig.Ieee8021xConfigs[i]
		if item.ProfileName == "" {
			continue
		}
		authProtocol := ieee8021x.AuthenticationProtocol(item.AuthenticationProtocol)
		if authProtocol == ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2 && item.Password == "" {
			err := f.PromptUserInput("Please enter password for "+item.ProfileName+": ", &item.Password)
			if err != nil {
				return err
			}
		}
		if authProtocol == ieee8021x.AuthenticationProtocolEAPTLS && item.PrivateKey == "" {
			err := f.PromptUserInput("Please enter private key for "+item.ProfileName+": ", &item.PrivateKey)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *Flags) verifyWifiConfigurations() error {
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

		authenticationMethod := wifi.AuthenticationMethod(cfg.AuthenticationMethod)
		switch authenticationMethod {
		case wifi.AuthenticationMethod_WPA_PSK:
			fallthrough
		case wifi.AuthenticationMethod_WPA2_PSK:
			if cfg.PskPassphrase == "" {
				log.Error("missing PskPassphrase for config: ", cfg.ProfileName)
				return utils.MissingOrInvalidConfiguration
			}
			break
		case wifi.AuthenticationMethod_WPA_IEEE8021x:
			fallthrough
		case wifi.AuthenticationMethod_WPA2_IEEE8021x:
			if cfg.ProfileName == "" {
				log.Error("missing ieee8021x profile name")
				return utils.MissingOrInvalidConfiguration
			}
			if cfg.PskPassphrase != "" {
				log.Errorf("wifi configuration for 8021x contains passphrase: %s", cfg.ProfileName)
				return utils.MissingOrInvalidConfiguration
			}
			err := f.verifyMatchingIeee8021xConfig(cfg.Ieee8021xProfileName)
			if err != nil {
				return err
			}
			break
		case wifi.AuthenticationMethod_Other:
			log.Errorf("unsupported AuthenticationMethod_Other (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_OpenSystem:
			log.Errorf("unsupported AuthenticationMethod_OpenSystem (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_SharedKey:
			log.Errorf("unsupported AuthenticationMethod_SharedKey (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_DMTFReserved:
			log.Errorf("unsupported AuthenticationMethod_DMTFReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_WPA3_SAE:
			log.Errorf("unsupported AuthenticationMethod_WPA3_SAE (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_WPA3_OWE:
			log.Errorf("unsupported AuthenticationMethod_WPA3_OWE (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_VendorReserved:
			log.Errorf("unsupported AuthenticationMethod_VendorReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		default:
			log.Errorf("invalid AuthenticationMethod_VendorReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}

		encryptionMethod := wifi.EncryptionMethod(cfg.EncryptionMethod)
		// NOTE: this is only
		switch encryptionMethod {
		case wifi.EncryptionMethod_TKIP:
			fallthrough
		case wifi.EncryptionMethod_CCMP:
			break
		case wifi.EncryptionMethod_Other:
			log.Errorf("unsupported EncryptionMethod_Other (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.EncryptionMethod_WEP:
			log.Errorf("unsupported EncryptionMethod_WEP (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.EncryptionMethod_None:
			log.Errorf("unsupported EncryptionMethod_None (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.EncryptionMethod_DMTFReserved:
			log.Errorf("unsupported EncryptionMethod_DMTFReserved (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		default:
			log.Errorf("invalid EncryptionMethod (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
	}
	return nil
}

func (f *Flags) verifyMatchingIeee8021xConfig(profileName string) error {
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
		err := f.verifyIeee8021xConfig(ieee802xCfg)
		if err != nil {
			return utils.MissingOrInvalidConfiguration
		}
	}
	if !foundOne {
		log.Error("missing IEEE802x Profile: ", profileName)
		return utils.MissingOrInvalidConfiguration
	}
	return nil
}

func (f *Flags) verifyIeee8021xConfig(cfg config.Ieee8021xConfig) error {
	var err error = utils.MissingOrInvalidConfiguration
	if cfg.Username == "" {
		log.Error("missing username for config: ", cfg.ProfileName)
		return err
	}
	if cfg.CACert == "" {
		log.Error("missing caCert for config: ", cfg.ProfileName)
		return err
	}
	authenticationProtocol := ieee8021x.AuthenticationProtocol(cfg.AuthenticationProtocol)
	// not all defined protocols are supported
	switch authenticationProtocol {
	case ieee8021x.AuthenticationProtocolEAPTLS:
		if cfg.ClientCert == "" {
			log.Error("missing clientCert for config: ", cfg.ProfileName)
			return err
		}
		if cfg.PrivateKey == "" {
			log.Error("missing privateKey for config: ", cfg.ProfileName)
			return err
		}
		break
	case ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2:
		if cfg.Password == "" {
			log.Error("missing password for for PEAPv0_EAPMSCHAPv2 config: ", cfg.ProfileName)
			return err
		}
		break
	case ieee8021x.AuthenticationProtocolEAPTTLS_MSCHAPv2:
		log.Errorf("unsupported AuthenticationProtocolEAPTTLS_MSCHAPv2 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolPEAPv1_EAPGTC:
		log.Errorf("unsupported AuthenticationProtocolPEAPv1_EAPGTC (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAPFAST_MSCHAPv2:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_MSCHAPv2 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAPFAST_GTC:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_GTC (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAP_MD5:
		log.Errorf("unsupported AuthenticationProtocolEAP_MD5 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAP_PSK:
		log.Errorf("unsupported AuthenticationProtocolEAP_PSK (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAP_SIM:
		log.Errorf("unsupported AuthenticationProtocolEAP_SIM (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAP_AKA:
		log.Errorf("unsupported AuthenticationProtocolEAP_AKA (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAPFAST_TLS:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_TLS (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	default:
		log.Errorf("invalid AuthenticationProtocol (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	}

	return nil
}
