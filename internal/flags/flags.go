/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package flags

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"rpc/internal/amt"
	"rpc/internal/config"
	"rpc/pkg/utils"
	"strconv"
	"time"

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
	commandLineArgs                      []string
	URL                                  string
	DNS                                  string
	Hostname                             string
	Proxy                                string
	Command                              string
	SubCommand                           string
	Profile                              string
	LMSAddress                           string
	LMSPort                              string
	SkipCertCheck                        bool
	Verbose                              bool
	Force                                bool
	JsonOutput                           bool
	RandomPassword                       bool
	Local                                bool
	StaticPassword                       string
	Password                             string
	LogLevel                             string
	Token                                string
	TenantID                             string
	UseCCM                               bool
	UseACM                               bool
	configContent                        string
	LocalConfig                          config.Config
	amtInfoCommand                       *flag.FlagSet
	amtActivateCommand                   *flag.FlagSet
	amtDeactivateCommand                 *flag.FlagSet
	amtMaintenanceCommand                *flag.FlagSet
	amtMaintenanceAddWiFiSettingsCommand *flag.FlagSet
	amtMaintenanceSyncIPCommand          *flag.FlagSet
	amtMaintenanceSyncClockCommand       *flag.FlagSet
	amtMaintenanceSyncHostnameCommand    *flag.FlagSet
	amtMaintenanceChangePasswordCommand  *flag.FlagSet
	versionCommand                       *flag.FlagSet
	amtConfigureCommand                  *flag.FlagSet
	amtConfigureAddWiFiSettingsCommand   *flag.FlagSet
	amtCommand                           amt.AMTCommand
	netEnumerator                        NetEnumerator
	IpConfiguration                      IPConfiguration
	HostnameInfo                         HostnameInfo
	AMTTimeoutDuration                   time.Duration
	FriendlyName                         string
	AmtInfo                              AmtInfoFlags
}

func NewFlags(args []string) *Flags {
	flags := &Flags{}
	flags.commandLineArgs = args
	flags.amtInfoCommand = flag.NewFlagSet(utils.CommandAMTInfo, flag.ContinueOnError)
	flags.amtInfoCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.amtActivateCommand = flag.NewFlagSet(utils.CommandActivate, flag.ContinueOnError)
	flags.amtDeactivateCommand = flag.NewFlagSet(utils.CommandDeactivate, flag.ContinueOnError)
	flags.amtMaintenanceCommand = flag.NewFlagSet(utils.CommandMaintenance, flag.ContinueOnError)

	flags.amtMaintenanceSyncIPCommand = flag.NewFlagSet("syncip", flag.ContinueOnError)
	flags.amtMaintenanceSyncClockCommand = flag.NewFlagSet("syncclock", flag.ContinueOnError)
	flags.amtMaintenanceSyncHostnameCommand = flag.NewFlagSet("synchostname", flag.ContinueOnError)
	flags.amtMaintenanceChangePasswordCommand = flag.NewFlagSet("changepassword", flag.ContinueOnError)
	flags.amtMaintenanceAddWiFiSettingsCommand = flag.NewFlagSet("addwifisettings", flag.ContinueOnError)

	flags.versionCommand = flag.NewFlagSet(utils.CommandVersion, flag.ContinueOnError)
	flags.versionCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.amtConfigureCommand = flag.NewFlagSet(utils.CommandConfigure, flag.ContinueOnError)
	flags.amtConfigureCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")
	flags.amtConfigureAddWiFiSettingsCommand = flag.NewFlagSet("addwifisettings", flag.ContinueOnError)

	flags.amtCommand = amt.NewAMTCommand()
	flags.netEnumerator = NetEnumerator{}
	flags.netEnumerator.Interfaces = net.Interfaces
	flags.netEnumerator.InterfaceAddrs = (*net.Interface).Addrs
	flags.setupCommonFlags()

	return flags
}

// ParseFlags is used for understanding the command line flags
func (f *Flags) ParseFlags() int {
	var resultCode int
	if len(f.commandLineArgs) > 1 {
		f.Command = f.commandLineArgs[1]
	}
	switch f.Command {
	case utils.CommandAMTInfo:
		resultCode = f.handleAMTInfo(f.amtInfoCommand)
	case utils.CommandActivate:
		resultCode = f.handleActivateCommand()
	case utils.CommandDeactivate:
		resultCode = f.handleDeactivateCommand()
	case utils.CommandMaintenance:
		resultCode = f.handleMaintenanceCommand()
	case utils.CommandVersion:
		resultCode = f.handleVersionCommand()
	case utils.CommandConfigure:
		resultCode = f.handleConfigureCommand()
	default:
		resultCode = utils.IncorrectCommandLineParameters
		f.printUsage()
	}
	return resultCode
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
		f.amtMaintenanceAddWiFiSettingsCommand,
		f.amtMaintenanceChangePasswordCommand,
		f.amtMaintenanceSyncClockCommand,
		f.amtMaintenanceSyncHostnameCommand,
		f.amtMaintenanceSyncIPCommand} {
		if fs.Name() != "addiwfisettings" { // addwifisettings does not require remote settings since it is local
			fs.StringVar(&f.URL, "u", "", "Websocket address of server to activate against") //required
			fs.BoolVar(&f.SkipCertCheck, "n", false, "Skip Websocket server certificate verification")
			fs.StringVar(&f.Proxy, "p", "", "Proxy address and port")
			fs.StringVar(&f.Token, "token", "", "JWT Token for Authorization")
			fs.StringVar(&f.TenantID, "tenant", "", "TenantID")
		}
		fs.StringVar(&f.LMSAddress, "lmsaddress", utils.LMSAddress, "LMS address. Can be used to change location of LMS for debugging.")
		fs.StringVar(&f.LMSPort, "lmsport", utils.LMSPort, "LMS port")
		fs.BoolVar(&f.Verbose, "v", false, "Verbose output")
		fs.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
		fs.BoolVar(&f.JsonOutput, "json", false, "JSON output")
		fs.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
		fs.DurationVar(&f.AMTTimeoutDuration, "t", 2*time.Minute, "AMT timeout - time to wait until AMT is ready (ex. '2m' or '30s')")
		if fs.Name() != "activate" { // activate does not use the -f flag
			fs.BoolVar(&f.Force, "f", false, "Force even if device is not registered with a server")
		}
	}
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

func (f *Flags) ReadPasswordFromUser() (bool, int) {
	fmt.Println("Please enter AMT Password: ")
	var password string
	_, err := fmt.Scanln(&password)
	if password == "" || err != nil {
		return false, utils.MissingOrIncorrectPassword
	}
	f.Password = password
	return true, utils.Success
}
