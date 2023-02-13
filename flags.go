/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpc

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"rpc/internal/amt"
	"rpc/pkg/utils"
	"strconv"
	"strings"
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
	commandLineArgs                     []string
	URL                                 string
	DNS                                 string
	Hostname                            string
	Proxy                               string
	Command                             string
	Profile                             string
	LMSAddress                          string
	LMSPort                             string
	SkipCertCheck                       bool
	Verbose                             bool
	JsonOutput                          bool
	RandomPassword                      bool
	StaticPassword                      string
	Password                            string
	LogLevel                            string
	Token                               string
	TenantID                            string
	amtInfoCommand                      *flag.FlagSet
	amtActivateCommand                  *flag.FlagSet
	amtDeactivateCommand                *flag.FlagSet
	amtMaintenanceCommand               *flag.FlagSet
	amtMaintenanceSyncIPCommand         *flag.FlagSet
	amtMaintenanceSyncClockCommand      *flag.FlagSet
	amtMaintenanceSyncHostnameCommand   *flag.FlagSet
	amtMaintenanceChangePasswordCommand *flag.FlagSet
	versionCommand                      *flag.FlagSet
	amtCommand                          amt.AMTCommand
	netEnumerator                       NetEnumerator
	IpConfiguration                     IPConfiguration
	HostnameInfo                        HostnameInfo
	AMTTimeoutDuration                  time.Duration
}

func NewFlags(args []string) *Flags {
	flags := &Flags{}
	flags.commandLineArgs = args
	flags.amtInfoCommand = flag.NewFlagSet("amtinfo", flag.ContinueOnError)
	flags.amtInfoCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.amtActivateCommand = flag.NewFlagSet("activate", flag.ContinueOnError)
	flags.amtDeactivateCommand = flag.NewFlagSet("deactivate", flag.ContinueOnError)
	flags.amtMaintenanceCommand = flag.NewFlagSet("maintenance", flag.ContinueOnError)

	flags.amtMaintenanceSyncIPCommand = flag.NewFlagSet("syncip", flag.ContinueOnError)
	flags.amtMaintenanceSyncClockCommand = flag.NewFlagSet("syncclock", flag.ContinueOnError)
	flags.amtMaintenanceSyncHostnameCommand = flag.NewFlagSet("synchostname", flag.ContinueOnError)
	flags.amtMaintenanceChangePasswordCommand = flag.NewFlagSet("changepassword", flag.ContinueOnError)

	flags.versionCommand = flag.NewFlagSet("version", flag.ContinueOnError)
	flags.versionCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.amtCommand = amt.NewAMTCommand()
	flags.netEnumerator = NetEnumerator{}
	flags.netEnumerator.Interfaces = net.Interfaces
	flags.netEnumerator.InterfaceAddrs = (*net.Interface).Addrs
	flags.setupCommonFlags()

	return flags
}

// ParseFlags is used for understanding the command line flags
func (f *Flags) ParseFlags() (string, int) {

	if len(f.commandLineArgs) > 1 {
		switch f.commandLineArgs[1] {
		case "amtinfo":
			f.handleAMTInfo(f.amtInfoCommand)
			return "amtinfo", 0 //we want to exit the program
		case "activate":
			result := f.handleActivateCommand()
			return "activate", result
		case "maintenance":
			result := f.handleMaintenanceCommand()
			return "maintenance", result
		case "deactivate":
			result := f.handleDeactivateCommand()
			return "deactivate", result
		case "version":
			f.handleVersionCommand()
			return "version", 0
		default:
			f.printUsage()
			return "", utils.Success
		}
	}
	f.printUsage()
	return "", utils.IncorrectCommandLineParameters

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

func (f *Flags) printMaintenanceUsage() string {
	executable := filepath.Base(os.Args[0])
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"
	usage = usage + "Usage: " + executable + " maintenance COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Maintenance Commands:\n"
	usage = usage + "  changepassword Change the AMT password. A random password is generated by default. Specify -static to set manually. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance changepassword -u wss://server/activate\n"
	usage = usage + "  syncclock      Sync the host OS clock to AMT. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance syncclock -u wss://server/activate\n"
	usage = usage + "  synchostname   Sync the hostname of the client to AMT. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance synchostname -u wss://server/activate\n"
	usage = usage + "  syncip         Sync the IP configuration of the host OS to AMT Network Settings. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance syncip -staticip 192.168.1.7 -netmask 255.255.255.0 -gateway 192.168.1.1 -primarydns 8.8.8.8 -secondarydns 4.4.4.4 -u wss://server/activate\n"
	usage = usage + "                 If a static ip is not specified, the ip address and netmask of the host OS is used\n"
	usage = usage + "\nRun '" + executable + " maintenance COMMAND -h' for more information on a command.\n"
	fmt.Println(usage)
	return usage
}

func (f *Flags) setupCommonFlags() {
	for _, fs := range []*flag.FlagSet{
		f.amtActivateCommand,
		f.amtDeactivateCommand,
		f.amtMaintenanceCommand,
		f.amtMaintenanceChangePasswordCommand,
		f.amtMaintenanceSyncClockCommand,
		f.amtMaintenanceSyncHostnameCommand,
		f.amtMaintenanceSyncIPCommand} {
		fs.StringVar(&f.URL, "u", "", "Websocket address of server to activate against") //required
		fs.BoolVar(&f.SkipCertCheck, "n", false, "Skip Websocket server certificate verification")
		fs.StringVar(&f.Proxy, "p", "", "Proxy address and port")
		fs.StringVar(&f.LMSAddress, "lmsaddress", utils.LMSAddress, "LMS address. Can be used to change location of LMS for debugging.")
		fs.StringVar(&f.LMSPort, "lmsport", utils.LMSPort, "LMS port")
		fs.BoolVar(&f.Verbose, "v", false, "Verbose output")
		fs.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
		fs.BoolVar(&f.JsonOutput, "json", false, "JSON output")
		fs.StringVar(&f.Token, "token", "", "JWT Token for Authorization")
		fs.StringVar(&f.TenantID, "tenant", "", "TenantID")
		fs.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
		fs.DurationVar(&f.AMTTimeoutDuration, "t", 2*time.Minute, "AMT timeout - time to wait until AMT is ready (ex. '2m' or '30s')")
	}
}

func (f *Flags) handleMaintenanceCommand() int {

	//validation section
	if len(f.commandLineArgs) == 2 {
		f.printMaintenanceUsage()
		return utils.IncorrectCommandLineParameters
	}

	var err error

	task := ""
	switch f.commandLineArgs[2] {
	case "syncclock":
		task = f.handleMaintenanceSyncClock()
	case "synchostname":
		task = f.handleMaintenanceSyncHostname()
	case "syncip":
		task, err = f.handleMaintenanceSyncIP()
	case "changepassword":
		task = f.handleMaintenanceSyncChangePassword()
	default:
		f.printMaintenanceUsage()
	}
	if task == "" || err != nil {
		// Parse the error message to find the problematic flag.
		// The problematic flag is of the following format '-' followed by flag name and then a ':'
		re := regexp.MustCompile(`-.*:`)
		switch re.FindString(err.Error()) {
		case "-netmask:":
			return utils.MissingOrIncorrectNetworkMask
		case "-staticip:":
			return utils.MissingOrIncorrectStaticIP
		case "-gateway:":
			return utils.MissingOrIncorrectGateway
		case "-primarydns:":
			return utils.MissingOrIncorrectPrimaryDNS
		case "-secondarydns:":
			return utils.MissingOrIncorrectSecondaryDNS
		default:
			return utils.IncorrectCommandLineParameters
		}
	}
	if f.URL == "" {
		fmt.Print("\n-u flag is required and cannot be empty\n\n")
		f.amtMaintenanceCommand.Usage()
		return utils.MissingOrIncorrectURL
	}
	if f.Password == "" {
		fmt.Println("Please enter the current AMT Password: ")
		_, err := fmt.Scanln(&f.Password)
		if f.Password == "" || err != nil {
			fmt.Print("\ncurrent AMT password is required and cannot be empty\n\n")
			f.amtMaintenanceCommand.Usage()
			return utils.MissingOrIncorrectPassword
		}
	}

	f.Command = fmt.Sprintf("maintenance --password %s %s", f.Password, task)
	return utils.Success
}

func (f *Flags) handleMaintenanceSyncClock() string {
	if err := f.amtMaintenanceSyncClockCommand.Parse(f.commandLineArgs[3:]); err != nil {
		return ""
	}
	return "--synctime"
}

func (f *Flags) handleMaintenanceSyncHostname() string {
	var err error
	if err = f.amtMaintenanceSyncHostnameCommand.Parse(f.commandLineArgs[3:]); err != nil {
		return ""
	}
	amtCommand := amt.NewAMTCommand()
	if f.HostnameInfo.DnsSuffixOS, err = amtCommand.GetOSDNSSuffix(); err != nil {
		log.Error(err)
	}
	f.HostnameInfo.Hostname, err = os.Hostname()
	if err != nil {
		log.Error(err)
		return ""
	} else if f.HostnameInfo.Hostname == "" {
		log.Error("OS hostname is not available")
		return ""
	}
	return "--synchostname"
}

// wrap the flag.Func method signature with the assignment value
func validateIP(assignee *string) func(string) error {
	return func(val string) error {
		if net.ParseIP(val) == nil {
			return errors.New("not a valid ip address")
		}
		*assignee = val
		return nil
	}
}

func (f *Flags) handleMaintenanceSyncIP() (string, error) {
	f.amtMaintenanceSyncIPCommand.Func(
		"staticip",
		"IP address to be assigned to AMT - if not specified, the IP Address of the active OS newtork interface is used",
		validateIP(&f.IpConfiguration.IpAddress))
	f.amtMaintenanceSyncIPCommand.Func(
		"netmask",
		"Network mask to be assigned to AMT - if not specified, the Network mask of the active OS newtork interface is used",
		validateIP(&f.IpConfiguration.Netmask))
	f.amtMaintenanceSyncIPCommand.Func("gateway", "Gateway address to be assigned to AMT", validateIP(&f.IpConfiguration.Gateway))
	f.amtMaintenanceSyncIPCommand.Func("primarydns", "Primary DNS to be assigned to AMT", validateIP(&f.IpConfiguration.PrimaryDns))
	f.amtMaintenanceSyncIPCommand.Func("secondarydns", "Secondary DNS to be assigned to AMT", validateIP(&f.IpConfiguration.SecondaryDns))

	if err := f.amtMaintenanceSyncIPCommand.Parse(f.commandLineArgs[3:]); err != nil {
		return "", err
	} else if len(f.IpConfiguration.IpAddress) != 0 {
		return "--syncip", err
	}

	amtLanIfc, err := f.amtCommand.GetLANInterfaceSettings(false)
	if err != nil {
		log.Error(err)
		return "", err
	}

	ifaces, err := f.netEnumerator.Interfaces()
	if err != nil {
		log.Error(err)
		return "", err
	}

	for _, i := range ifaces {
		if len(f.IpConfiguration.IpAddress) != 0 {
			break
		}
		if i.HardwareAddr.String() != amtLanIfc.MACAddress {
			continue
		}
		addrs, _ := f.netEnumerator.InterfaceAddrs(&i)
		if err != nil {
			continue
		}
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok &&
				ipnet.IP.To4() != nil &&
				!ipnet.IP.IsLoopback() {
				f.IpConfiguration.IpAddress = ipnet.IP.String()
				f.IpConfiguration.Netmask = net.IP(ipnet.Mask).String()
			}
		}
	}

	if len(f.IpConfiguration.IpAddress) == 0 {
		log.Errorf("static ip address not found")
		return "", err
	}
	return "--syncip", err
}

func (f *Flags) handleMaintenanceSyncChangePassword() string {
	task := "--changepassword "
	f.amtMaintenanceChangePasswordCommand.BoolVar(&f.RandomPassword, "random", true, "a new random password will be generated for AMT")
	f.amtMaintenanceChangePasswordCommand.StringVar(&f.StaticPassword, "static", "", "specify a new password for AMT")
	if err := f.amtMaintenanceChangePasswordCommand.Parse(f.commandLineArgs[3:]); err != nil {
		f.amtMaintenanceChangePasswordCommand.Usage()
		return ""
	}
	if f.StaticPassword == "" && !f.RandomPassword {
		f.amtMaintenanceChangePasswordCommand.Usage()
		return ""
	}
	if f.StaticPassword != "" {
		task += f.StaticPassword
	}

	return task
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

func (f *Flags) handleActivateCommand() int {
	f.amtActivateCommand.StringVar(&f.DNS, "d", f.lookupEnvOrString("DNS_SUFFIX", ""), "dns suffix override")
	f.amtActivateCommand.StringVar(&f.Hostname, "h", f.lookupEnvOrString("HOSTNAME", ""), "hostname override")
	f.amtActivateCommand.StringVar(&f.Profile, "profile", f.lookupEnvOrString("PROFILE", ""), "name of the profile to use")

	if len(f.commandLineArgs) == 2 {
		f.amtActivateCommand.PrintDefaults()
		return utils.IncorrectCommandLineParameters
	}
	if err := f.amtActivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		re := regexp.MustCompile(`: .*`)
		switch re.FindString(err.Error()) {
		case ": -d":
			return utils.MissingDNSSuffix
		case ": -p":
			return utils.MissingProxyAddressAndPort
		case ": -h":
			return utils.MissingHostname
		case ": -profile":
			return utils.MissingOrIncorrectProfile
		default:
			return utils.IncorrectCommandLineParameters
		}
	}

	if f.amtActivateCommand.Parsed() {
		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtActivateCommand.Usage()
			return utils.MissingOrIncorrectURL
		}
		if f.Profile == "" {
			fmt.Println("-profile flag is required and cannot be empty")
			f.amtActivateCommand.Usage()
			return utils.MissingOrIncorrectProfile
		}
	}
	f.Command = "activate --profile " + f.Profile
	return utils.Success
}

func (f *Flags) handleDeactivateCommand() int {
	forcePtr := f.amtDeactivateCommand.Bool("f", false, "force deactivate even if device is not registered with a server")

	if len(f.commandLineArgs) == 2 {
		f.amtDeactivateCommand.PrintDefaults()
		return utils.IncorrectCommandLineParameters
	}
	if err := f.amtDeactivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}

	if f.amtDeactivateCommand.Parsed() {
		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtDeactivateCommand.Usage()
			return utils.MissingOrIncorrectURL
		}
		if f.Password == "" {
			fmt.Println("Please enter AMT Password: ")
			var password string
			// Taking input from user
			_, err := fmt.Scanln(&password)
			if password == "" || err != nil {
				return utils.MissingOrIncorrectPassword
			}
			f.Password = password
		}
		f.Command = "deactivate --password " + f.Password
		if *forcePtr {
			f.Command = f.Command + " -f"
		}
	}
	return utils.Success
}
func (f *Flags) handleAMTInfo(amtInfoCommand *flag.FlagSet) int {
	amtInfoVerPtr := amtInfoCommand.Bool("ver", false, "BIOS Version")
	amtInfoBldPtr := amtInfoCommand.Bool("bld", false, "Build Number")
	amtInfoSkuPtr := amtInfoCommand.Bool("sku", false, "Product SKU")
	amtInfoUUIDPtr := amtInfoCommand.Bool("uuid", false, "Unique Identifier")
	amtInfoModePtr := amtInfoCommand.Bool("mode", false, "Current Control Mode")
	amtInfoDNSPtr := amtInfoCommand.Bool("dns", false, "Domain Name Suffix")
	amtInfoCertPtr := amtInfoCommand.Bool("cert", false, "Certificate Hashes")
	amtInfoRasPtr := amtInfoCommand.Bool("ras", false, "Remote Access Status")
	amtInfoLanPtr := amtInfoCommand.Bool("lan", false, "LAN Settings")
	amtInfoHostnamePtr := amtInfoCommand.Bool("hostname", false, "OS Hostname")

	if err := f.amtInfoCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}

	defaultFlagCount := 2
	if f.JsonOutput {
		defaultFlagCount = defaultFlagCount + 1
	}
	if len(f.commandLineArgs) == defaultFlagCount {

		*amtInfoVerPtr = true
		*amtInfoBldPtr = true
		*amtInfoSkuPtr = true
		*amtInfoUUIDPtr = true
		*amtInfoModePtr = true
		*amtInfoDNSPtr = true
		*amtInfoCertPtr = false
		*amtInfoRasPtr = true
		*amtInfoLanPtr = true
		*amtInfoHostnamePtr = true
	}
	dataStruct := make(map[string]interface{})

	if amtInfoCommand.Parsed() {
		amtCommand := amt.NewAMTCommand()
		if *amtInfoVerPtr {
			result, err := amtCommand.GetVersionDataFromME("AMT", f.AMTTimeoutDuration)
			if err != nil {
				log.Error(err)
			}
			dataStruct["amt"] = result
			if !f.JsonOutput {
				println("Version			: " + result)
			}
		}
		if *amtInfoBldPtr {
			result, err := amtCommand.GetVersionDataFromME("Build Number", f.AMTTimeoutDuration)
			if err != nil {
				log.Error(err)
			}
			dataStruct["buildNumber"] = result

			if !f.JsonOutput {
				println("Build Number		: " + result)
			}
		}
		if *amtInfoSkuPtr {
			result, err := amtCommand.GetVersionDataFromME("Sku", f.AMTTimeoutDuration)
			if err != nil {
				log.Error(err)
			}
			dataStruct["sku"] = result

			if !f.JsonOutput {
				println("SKU			: " + result)
			}
		}
		if *amtInfoUUIDPtr {
			result, err := amtCommand.GetUUID()
			if err != nil {
				log.Error(err)
			}
			dataStruct["uuid"] = result

			if !f.JsonOutput {
				println("UUID			: " + result)
			}
		}
		if *amtInfoModePtr {
			result, err := amtCommand.GetControlMode()
			if err != nil {
				log.Error(err)
			}
			dataStruct["controlMode"] = utils.InterpretControlMode(result)

			if !f.JsonOutput {
				println("Control Mode		: " + string(utils.InterpretControlMode(result)))
			}
		}
		if *amtInfoDNSPtr {
			result, err := amtCommand.GetDNSSuffix()
			if err != nil {
				log.Error(err)
			}
			dataStruct["dnsSuffix"] = result

			if !f.JsonOutput {
				println("DNS Suffix		: " + string(result))
			}
			result, err = amtCommand.GetOSDNSSuffix()
			if err != nil {
				log.Error(err)
			}
			dataStruct["dnsSuffixOS"] = result

			if !f.JsonOutput {
				fmt.Println("DNS Suffix (OS)		: " + result)
			}
		}
		if *amtInfoHostnamePtr {
			result, err := os.Hostname()
			if err != nil {
				log.Error(err)
			}
			dataStruct["hostnameOS"] = result
			if !f.JsonOutput {
				println("Hostname (OS)		: " + string(result))
			}
		}

		if *amtInfoRasPtr {
			result, err := amtCommand.GetRemoteAccessConnectionStatus()
			if err != nil {
				log.Error(err)
			}
			dataStruct["ras"] = result

			if !f.JsonOutput {
				println("RAS Network      	: " + result.NetworkStatus)
				println("RAS Remote Status	: " + result.RemoteStatus)
				println("RAS Trigger      	: " + result.RemoteTrigger)
				println("RAS MPS Hostname 	: " + result.MPSHostname)
			}
		}
		if *amtInfoLanPtr {
			wired, err := amtCommand.GetLANInterfaceSettings(false)
			if err != nil {
				log.Error(err)
			}
			dataStruct["wiredAdapter"] = wired

			if !f.JsonOutput && wired.MACAddress != "00:00:00:00:00:00" {
				println("---Wired Adapter---")
				println("DHCP Enabled 		: " + strconv.FormatBool(wired.DHCPEnabled))
				println("DHCP Mode    		: " + wired.DHCPMode)
				println("Link Status  		: " + wired.LinkStatus)
				println("IP Address   		: " + wired.IPAddress)
				println("MAC Address  		: " + wired.MACAddress)
			}

			wireless, err := amtCommand.GetLANInterfaceSettings(true)
			if err != nil {
				log.Error(err)
			}
			dataStruct["wirelessAdapter"] = wireless

			if !f.JsonOutput {
				println("---Wireless Adapter---")
				println("DHCP Enabled 		: " + strconv.FormatBool(wireless.DHCPEnabled))
				println("DHCP Mode    		: " + wireless.DHCPMode)
				println("Link Status  		: " + wireless.LinkStatus)
				println("IP Address   		: " + wireless.IPAddress)
				println("MAC Address  		: " + wireless.MACAddress)
			}
		}
		if *amtInfoCertPtr {
			result, err := amtCommand.GetCertificateHashes()
			if err != nil {
				log.Error(err)
			}
			certs := make(map[string]interface{})
			for _, v := range result {
				certs[v.Name] = v
			}
			dataStruct["certificateHashes"] = certs
			if !f.JsonOutput {
				println("Certificate Hashes	:")
				for _, v := range result {
					print(v.Name + " (")
					if v.IsDefault {
						print("Default,")
					}
					if v.IsActive {
						print("Active)")
					}
					println()
					println("   " + v.Algorithm + ": " + v.Hash)
				}
			}
		}
		if f.JsonOutput {
			outBytes, err := json.MarshalIndent(dataStruct, "", "  ")
			output := string(outBytes)
			if err != nil {
				output = err.Error()
			}
			println(output)
		}
	}
	return utils.Success
}

func (f *Flags) handleVersionCommand() int {

	if err := f.versionCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}

	if !f.JsonOutput {
		println(strings.ToUpper(utils.ProjectName))
		println("Version " + utils.ProjectVersion)
		println("Protocol " + utils.ProtocolVersion)
	}

	if f.JsonOutput {
		dataStruct := make(map[string]interface{})

		projectName := strings.ToUpper(utils.ProjectName)
		dataStruct["app"] = projectName

		projectVersion := utils.ProjectVersion
		dataStruct["version"] = projectVersion

		protocolVersion := utils.ProtocolVersion
		dataStruct["protocol"] = protocolVersion

		outBytes, err := json.MarshalIndent(dataStruct, "", "  ")
		output := string(outBytes)
		if err != nil {
			output = err.Error()
		}
		println(output)
	}

	return utils.Success
}
