/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpc

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"rpc/internal/amt"
	"rpc/pkg/utils"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Flags holds data received from the command line
type Flags struct {
	commandLineArgs       []string
	URL                   string
	DNS                   string
	Hostname              string
	Proxy                 string
	Command               string
	Profile               string
	LMSAddress            string
	LMSPort               string
	SkipCertCheck         bool
	Verbose               bool
	JsonOutput            bool
	SyncClock             bool
	Password              string
	LogLevel              string
	amtInfoCommand        *flag.FlagSet
	amtActivateCommand    *flag.FlagSet
	amtDeactivateCommand  *flag.FlagSet
	amtMaintenanceCommand *flag.FlagSet
	versionCommand        *flag.FlagSet
}

func NewFlags(args []string) *Flags {
	flags := &Flags{}
	flags.commandLineArgs = args
	flags.amtInfoCommand = flag.NewFlagSet("amtinfo", flag.ContinueOnError)
	flags.amtInfoCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.amtActivateCommand = flag.NewFlagSet("activate", flag.ContinueOnError)
	flags.amtDeactivateCommand = flag.NewFlagSet("deactivate", flag.ContinueOnError)
	flags.amtMaintenanceCommand = flag.NewFlagSet("maintenance", flag.ContinueOnError)

	flags.versionCommand = flag.NewFlagSet("version", flag.ContinueOnError)
	flags.versionCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.setupCommonFlags()
	return flags
}

// ParseFlags is used for understanding the command line flags
func (f *Flags) ParseFlags() (string, bool) {

	if len(f.commandLineArgs) > 1 {
		switch f.commandLineArgs[1] {
		case "amtinfo":
			f.handleAMTInfo(f.amtInfoCommand)
			return "amtinfo", false //we want to exit the program
		case "activate":
			success := f.handleActivateCommand()
			return "activate", success
		case "maintenance":
			success := f.handleMaintenanceCommand()
			return "maintenance", success
		case "deactivate":
			success := f.handleDeactivateCommand()
			return "deactivate", success
		case "version":
			f.handleVersionCommand()
			return "version", false
		default:
			f.printUsage()
			return "", false
		}
	}
	f.printUsage()
	return "", false

}
func (f *Flags) printUsage() string {
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, and status of AMT\n\n"
	usage = usage + "Usage: rpc COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Commands:\n"
	usage = usage + "  activate    Activate this device with a specified profile\n"
	usage = usage + "              Example: ./rpc activate -u wss://server/activate --profile acmprofile\n"
	usage = usage + "  deactivate  Deactivates this device. AMT password is required\n"
	usage = usage + "              Example: ./rpc deactivate -u wss://server/activate\n"
	usage = usage + "  maintenance Maintain this device.\n"
	usage = usage + "              Example: ./rpc maintenance -u wss://server/activate\n"
	usage = usage + "  amtinfo     Displays information about AMT status and configuration\n"
	usage = usage + "              Example: ./rpc amtinfo\n"
	usage = usage + "  version     Displays the current version of RPC and the RPC Protocol version\n"
	usage = usage + "              Example: ./rpc version\n"
	usage = usage + "\nRun 'rpc COMMAND' for more information on a command.\n"
	fmt.Println(usage)
	return usage
}

func (f *Flags) setupCommonFlags() {
	for _, fs := range []*flag.FlagSet{f.amtActivateCommand, f.amtDeactivateCommand, f.amtMaintenanceCommand} {
		fs.StringVar(&f.URL, "u", "", "websocket address of server to activate against") //required
		fs.BoolVar(&f.SkipCertCheck, "n", false, "skip websocket server certificate verification")
		fs.StringVar(&f.Proxy, "p", "", "proxy address and port")
		fs.StringVar(&f.LMSAddress, "lmsaddress", utils.LMSAddress, "lms address")
		fs.StringVar(&f.LMSPort, "lmsport", utils.LMSPort, "lms port")
		fs.BoolVar(&f.Verbose, "v", false, "verbose output")
		fs.StringVar(&f.LogLevel, "l", "info", "log level (panic,fatal,error,warn,info,debug,trace)")
		fs.BoolVar(&f.JsonOutput, "json", false, "json output")
	}
}
func (f *Flags) handleMaintenanceCommand() bool {
	f.amtActivateCommand.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
	f.amtMaintenanceCommand.BoolVar(&f.SyncClock, "c", false, "sync AMT clock")

	if len(f.commandLineArgs) == 2 {
		f.amtMaintenanceCommand.PrintDefaults()
		return false
	}
	if err := f.amtMaintenanceCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return false
	}
	if f.amtMaintenanceCommand.Parsed() {
		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtActivateCommand.Usage()
			return false
		}
		if f.Password == "" {
			fmt.Println("Please enter AMT Password: ")
			var password string
			// Taking input from user
			_, err := fmt.Scanln(&password)
			if password == "" || err != nil {
				return false
			}
			f.Password = password
		}
	}
	f.Command = "maintenance --synctime --password " + f.Password
	return true
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

func (f *Flags) handleActivateCommand() bool {
	f.amtActivateCommand.StringVar(&f.DNS, "d", f.lookupEnvOrString("DNS_SUFFIX", ""), "dns suffix override")
	f.amtActivateCommand.StringVar(&f.Hostname, "h", f.lookupEnvOrString("HOSTNAME", ""), "hostname override")
	f.amtActivateCommand.StringVar(&f.Profile, "profile", f.lookupEnvOrString("PROFILE", ""), "name of the profile to use")
	f.amtActivateCommand.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")

	if len(f.commandLineArgs) == 2 {
		f.amtActivateCommand.PrintDefaults()
		return false
	}
	if err := f.amtActivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return false
	}

	if f.amtActivateCommand.Parsed() {
		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtActivateCommand.Usage()
			return false
		}
		if f.Profile == "" {
			fmt.Println("-profile flag is required and cannot be empty")
			f.amtActivateCommand.Usage()
			return false
		}
	}
	f.Command = "activate --profile " + f.Profile
	return true
}
func (f *Flags) handleDeactivateCommand() bool {
	f.amtDeactivateCommand.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
	forcePtr := f.amtDeactivateCommand.Bool("f", false, "force deactivate even if device is not registered with a server")

	if len(f.commandLineArgs) == 2 {
		f.amtDeactivateCommand.PrintDefaults()
		return false
	}
	if err := f.amtDeactivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return false
	}

	if f.amtDeactivateCommand.Parsed() {
		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtDeactivateCommand.Usage()
			return false
		}
		if f.Password == "" {
			fmt.Println("Please enter AMT Password: ")
			var password string
			// Taking input from user
			_, err := fmt.Scanln(&password)
			if password == "" || err != nil {
				return false
			}
			f.Password = password
		}
		f.Command = "deactivate --password " + f.Password
		if *forcePtr {
			f.Command = f.Command + " -f"
		}
	}
	return true
}
func (f *Flags) handleAMTInfo(amtInfoCommand *flag.FlagSet) {
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
		return
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
			result, err := amtCommand.GetVersionDataFromME("AMT")
			if err != nil {
				log.Error(err)
			}
			dataStruct["amt"] = result
			if !f.JsonOutput {
				println("Version			: " + result)
			}
		}
		if *amtInfoBldPtr {
			result, err := amtCommand.GetVersionDataFromME("Build Number")
			if err != nil {
				log.Error(err)
			}
			dataStruct["buildNumber"] = result

			if !f.JsonOutput {
				println("Build Number		: " + result)
			}
		}
		if *amtInfoSkuPtr {
			result, err := amtCommand.GetVersionDataFromME("Sku")
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
}

func (f *Flags) handleVersionCommand() bool {

	if err := f.versionCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return false
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

	return true
}
