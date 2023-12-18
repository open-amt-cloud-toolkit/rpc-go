/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package flags

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"rpc/internal/amt"
	"rpc/internal/config"
	"rpc/internal/smb"
	"rpc/pkg/utils"
	"strconv"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	log "github.com/sirupsen/logrus"
)

// A NetEnumerator enumerates local IP addresses.
type NetEnumerator struct {
	Interfaces     func() ([]net.Interface, error)
	InterfaceAddrs func(*net.Interface) ([]net.Addr, error)
}

type IPConfiguration struct {
	IpAddress    string `json:"ipAddress"`
	Netmask      string `json:"netmask"`
	Gateway      string `json:"gateway"`
	PrimaryDns   string `json:"primaryDns"`
	SecondaryDns string `json:"secondaryDns"`
}

type HostnameInfo struct {
	DnsSuffixOS string `json:"dnsSuffixOS"`
	Hostname    string `json:"hostname"`
}

// Flags holds data received from the command line
type Flags struct {
	commandLineArgs                     []string
	URL                                 string
	DNS                                 string
	Hostname                            string
	Proxy                               string
	Command                             string
	SubCommand                          string
	Profile                             string
	LMSAddress                          string
	LMSPort                             string
	SkipCertCheck                       bool
	Verbose                             bool
	Force                               bool
	JsonOutput                          bool
	RandomPassword                      bool
	Local                               bool
	StaticPassword                      string
	Password                            string
	LogLevel                            string
	Token                               string
	TenantID                            string
	UseCCM                              bool
	UseACM                              bool
	configContent                       string
	UUID                                string
	LocalConfig                         config.Config
	amtInfoCommand                      *flag.FlagSet
	amtActivateCommand                  *flag.FlagSet
	amtDeactivateCommand                *flag.FlagSet
	amtMaintenanceSyncIPCommand         *flag.FlagSet
	amtMaintenanceSyncClockCommand      *flag.FlagSet
	amtMaintenanceSyncHostnameCommand   *flag.FlagSet
	amtMaintenanceChangePasswordCommand *flag.FlagSet
	amtMaintenanceSyncDeviceInfoCommand *flag.FlagSet
	versionCommand                      *flag.FlagSet
	flagSetAddWifiSettings              *flag.FlagSet
	flagSetEnableWifiPort               *flag.FlagSet
	amtCommand                          amt.AMTCommand
	netEnumerator                       NetEnumerator
	IpConfiguration                     IPConfiguration
	HostnameInfo                        HostnameInfo
	AMTTimeoutDuration                  time.Duration
	FriendlyName                        string
	AmtInfo                             AmtInfoFlags
	SkipIPRenew                         bool
	SambaService                        smb.ServiceInterface
}

func NewFlags(args []string) *Flags {
	flags := &Flags{}
	flags.commandLineArgs = args
	flags.amtInfoCommand = flag.NewFlagSet(utils.CommandAMTInfo, flag.ContinueOnError)
	flags.amtInfoCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.amtActivateCommand = flag.NewFlagSet(utils.CommandActivate, flag.ContinueOnError)
	flags.amtDeactivateCommand = flag.NewFlagSet(utils.CommandDeactivate, flag.ContinueOnError)

	flags.amtMaintenanceSyncIPCommand = flag.NewFlagSet(utils.SubCommandSyncIP, flag.ContinueOnError)
	flags.amtMaintenanceSyncClockCommand = flag.NewFlagSet(utils.SubCommandSyncClock, flag.ContinueOnError)
	flags.amtMaintenanceSyncHostnameCommand = flag.NewFlagSet(utils.SubCommandSyncHostname, flag.ContinueOnError)
	flags.amtMaintenanceChangePasswordCommand = flag.NewFlagSet(utils.SubCommandChangePassword, flag.ContinueOnError)
	flags.amtMaintenanceSyncDeviceInfoCommand = flag.NewFlagSet(utils.SubCommandSyncDeviceInfo, flag.ContinueOnError)

	flags.versionCommand = flag.NewFlagSet(utils.CommandVersion, flag.ContinueOnError)
	flags.versionCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.flagSetAddWifiSettings = flag.NewFlagSet(utils.SubCommandAddWifiSettings, flag.ContinueOnError)
	flags.flagSetEnableWifiPort = flag.NewFlagSet(utils.SubCommandEnableWifiPort, flag.ContinueOnError)

	flags.amtCommand = amt.NewAMTCommand()
	flags.netEnumerator = NetEnumerator{}
	flags.netEnumerator.Interfaces = net.Interfaces
	flags.netEnumerator.InterfaceAddrs = (*net.Interface).Addrs
	flags.setupCommonFlags()

	flags.SambaService = smb.NewSambaService()

	return flags
}

// ParseFlags is used for understanding the command line flags
func (f *Flags) ParseFlags() utils.ReturnCode {
	var rc utils.ReturnCode
	if len(f.commandLineArgs) > 1 {
		f.Command = f.commandLineArgs[1]
	}
	switch f.Command {
	case utils.CommandAMTInfo:
		rc = f.handleAMTInfo(f.amtInfoCommand)
	case utils.CommandActivate:
		rc = f.handleActivateCommand()
	case utils.CommandDeactivate:
		rc = f.handleDeactivateCommand()
	case utils.CommandMaintenance:
		rc = f.handleMaintenanceCommand()
	case utils.CommandVersion:
		rc = f.handleVersionCommand()
	case utils.CommandConfigure:
		rc = f.handleConfigureCommand()
	default:
		rc = utils.IncorrectCommandLineParameters
		f.printUsage()
	}
	return rc
}

func (f *Flags) printUsage() string {
	executable := filepath.Base(os.Args[0])
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"
	usage = usage + "Usage: " + executable + " COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Commands:\n"
	usage = usage + "  activate    Activate this device with a specified profile\n"
	usage = usage + "              Example: " + executable + " activate -u wss://server/activate --profile acmprofile\n"
	usage = usage + "  amtinfo     Displays information about AMT status and configuration\n"
	usage = usage + "              Example: " + executable + " amtinfo\n"
	usage = usage + "  configure   Local configuration of a feature on this device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " configure addwifisettings ...\n"
	usage = usage + "  deactivate  Deactivates this device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " deactivate -u wss://server/activate\n"
	usage = usage + "  maintenance Execute a maintenance task for the device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " maintenance syncclock -u wss://server/activate \n"
	usage = usage + "  version     Displays the current version of RPC and the RPC Protocol version\n"
	usage = usage + "              Example: " + executable + " version\n"
	usage = usage + "\nRun '" + executable + " COMMAND' for more information on a command.\n"
	fmt.Println(usage)
	return usage
}

func (f *Flags) setupCommonFlags() {
	for _, fs := range []*flag.FlagSet{
		f.amtActivateCommand,
		f.amtDeactivateCommand,
		f.amtMaintenanceChangePasswordCommand,
		f.amtMaintenanceSyncDeviceInfoCommand,
		f.amtMaintenanceSyncClockCommand,
		f.amtMaintenanceSyncHostnameCommand,
		f.amtMaintenanceSyncIPCommand} {
		fs.StringVar(&f.URL, "u", "", "Websocket address of server to activate against") //required
		fs.BoolVar(&f.SkipCertCheck, "n", false, "Skip Websocket server certificate verification")
		fs.StringVar(&f.Proxy, "p", "", "Proxy address and port")
		fs.StringVar(&f.Token, "token", "", "JWT Token for Authorization")
		fs.StringVar(&f.TenantID, "tenant", "", "TenantID")
		fs.StringVar(&f.LMSAddress, "lmsaddress", utils.LMSAddress, "LMS address. Can be used to change location of LMS for debugging.")
		fs.StringVar(&f.LMSPort, "lmsport", utils.LMSPort, "LMS port")
		fs.BoolVar(&f.Verbose, "v", false, "Verbose output")
		fs.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
		fs.BoolVar(&f.JsonOutput, "json", false, "JSON output")
		fs.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
		fs.DurationVar(&f.AMTTimeoutDuration, "t", 2*time.Minute, "AMT timeout - time to wait until AMT is ready (ex. '2m' or '30s')")
		if fs.Name() != utils.CommandActivate { // activate does not use the -f flag
			fs.BoolVar(&f.Force, "f", false, "Force even if device is not registered with a server")
		}
		if fs.Name() != utils.CommandDeactivate { // activate does not use the -f flag
			fs.StringVar(&f.UUID, "uuid", "", "override AMT device uuid for use with non-CIRA workflow")
		}
	}
}

func (f *Flags) validateUUIDOverride() utils.ReturnCode {
	uuidPattern := regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
	if matched := uuidPattern.MatchString(f.UUID); !matched {
		fmt.Println("uuid provided does not follow proper uuid format")
		return utils.InvalidUUID
	}
	return utils.Success
}

func (f *Flags) lookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
func (f *Flags) lookupEnvOrBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		parsedVal, err := strconv.ParseBool(val)
		if err != nil {
			log.Error(err)
			return false
		}
		return parsedVal
	}
	return defaultVal
}

func (f *Flags) PromptUserInput(prompt string, value *string) utils.ReturnCode {
	fmt.Println(prompt)
	_, err := fmt.Scanln(value)
	if err != nil {
		log.Error(err)
		return utils.InvalidUserInput
	}
	return utils.Success
}

func (f *Flags) ReadPasswordFromUser() (bool, utils.ReturnCode) {
	fmt.Println("Please enter AMT Password: ")
	var password string
	_, err := fmt.Scanln(&password)
	if password == "" || err != nil {
		return false, utils.MissingOrIncorrectPassword
	}
	f.Password = password
	return true, utils.Success
}

func (f *Flags) handleLocalConfig() utils.ReturnCode {
	if f.configContent == "" {
		return utils.Success
	}
	ext := filepath.Ext(strings.ToLower(f.configContent))
	isPFX := ext == ".pfx"
	if strings.HasPrefix(f.configContent, "smb:") {
		isJSON := ext == ".json"
		isYAML := ext == ".yaml" || ext == ".yml"
		if !isPFX && !isJSON && !isYAML {
			log.Error("remote config unsupported smb file extension: ", ext)
			return utils.FailedReadingConfiguration
		}
		configBytes, err := f.SambaService.FetchFileContents(f.configContent)
		if err != nil {
			log.Error("config error: ", err)
			return utils.FailedReadingConfiguration
		}
		if isPFX {
			f.LocalConfig.ACMSettings.ProvisioningCert = base64.StdEncoding.EncodeToString(configBytes)
		}
		if isJSON {
			err = cleanenv.ParseJSON(bytes.NewReader(configBytes), &f.LocalConfig)
		}
		if isYAML {
			err = cleanenv.ParseYAML(bytes.NewReader(configBytes), &f.LocalConfig)
		}
		if err != nil {
			log.Error("config error: ", err)
			return utils.FailedReadingConfiguration
		}
	} else if isPFX {
		pfxBytes, err := os.ReadFile(f.configContent)
		if err != nil {
			log.Error("config error: ", err)
			return utils.FailedReadingConfiguration
		}
		f.LocalConfig.ACMSettings.ProvisioningCert = base64.StdEncoding.EncodeToString(pfxBytes)
	} else {
		err := cleanenv.ReadConfig(f.configContent, &f.LocalConfig)
		if err != nil {
			log.Error("config error: ", err)
			return utils.FailedReadingConfiguration
		}
	}
	return utils.Success
}
