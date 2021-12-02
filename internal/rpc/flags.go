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
	SkipCertCheck         bool
	Verbose               bool
	JsonOutput            bool
	SyncClock             bool
	Password              string
	amtInfoCommand        *flag.FlagSet
	amtActivateCommand    *flag.FlagSet
	amtDeactivateCommand  *flag.FlagSet
	amtMaintenanceCommand *flag.FlagSet
}

func NewFlags(args []string) *Flags {
	flags := &Flags{}
	flags.commandLineArgs = args
	flags.amtInfoCommand = flag.NewFlagSet("amtinfo", flag.ExitOnError)
	flags.amtInfoCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.amtActivateCommand = flag.NewFlagSet("activate", flag.ExitOnError)
	flags.amtActivateCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")
	flags.amtDeactivateCommand = flag.NewFlagSet("deactivate", flag.ExitOnError)
	flags.amtDeactivateCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")
	flags.amtMaintenanceCommand = flag.NewFlagSet("maintenance", flag.ExitOnError)
	flags.amtMaintenanceCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")
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
			println(strings.ToUpper(utils.ProjectName))
			println("Version " + utils.ProjectVersion)
			println("Protocol " + utils.ProtocolVersion)
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
		fs.BoolVar(&f.Verbose, "v", false, "verbose output")
	}
}
func (f *Flags) handleMaintenanceCommand() bool {
	f.amtActivateCommand.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
	f.amtMaintenanceCommand.BoolVar(&f.SyncClock, "c", false, "sync AMT clock")

	if len(f.commandLineArgs) == 2 {
		f.amtMaintenanceCommand.PrintDefaults()
		return false
	}
	f.amtMaintenanceCommand.Parse(f.commandLineArgs[2:])
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
	f.amtActivateCommand.Parse(f.commandLineArgs[2:])

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
	f.amtDeactivateCommand.Parse(f.commandLineArgs[2:])

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

	amtInfoCommand.Parse(f.commandLineArgs[2:])

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
		amt := amt.NewAMTCommand()
		if *amtInfoVerPtr {
			result, _ := amt.GetVersionDataFromME("AMT")
			dataStruct["AMT"] = result
			if !f.JsonOutput {
				println("Version			: " + result)
			}
		}
		if *amtInfoBldPtr {
			result, _ := amt.GetVersionDataFromME("Build Number")
			dataStruct["Build Number"] = result

			if !f.JsonOutput {
				println("Build Number		: " + result)
			}
		}
		if *amtInfoSkuPtr {
			result, _ := amt.GetVersionDataFromME("Sku")
			dataStruct["SKU"] = result

			if !f.JsonOutput {
				println("SKU			: " + result)
			}
		}
		if *amtInfoUUIDPtr {
			result, _ := amt.GetUUID()
			dataStruct["UUID"] = result

			if !f.JsonOutput {
				println("UUID			: " + result)
			}
		}
		if *amtInfoModePtr {
			result, _ := amt.GetControlMode()
			dataStruct["Control Mode (Raw)"] = result
			dataStruct["Control Mode"] = string(utils.InterpretControlMode(result))

			if !f.JsonOutput {
				println("Control Mode		: " + string(utils.InterpretControlMode(result)))
			}
		}
		if *amtInfoDNSPtr {
			result, _ := amt.GetDNSSuffix()
			dataStruct["DNS Suffix"] = result

			if !f.JsonOutput {
				println("DNS Suffix		: " + string(result))
			}
			result, _ = amt.GetOSDNSSuffix()
			dataStruct["DNS Suffix (OS)"] = result

			if !f.JsonOutput {
				fmt.Println("DNS Suffix (OS)		: " + result)
			}
		}
		if *amtInfoHostnamePtr {
			result, _ := os.Hostname()
			dataStruct["Hostname (OS)"] = result
			if !f.JsonOutput {

				println("Hostname (OS)		: " + string(result))
			}
		}

		if *amtInfoRasPtr {
			result, _ := amt.GetRemoteAccessConnectionStatus()
			dataStruct["RAS"] = result

			if !f.JsonOutput {
				println("RAS Network      	: " + result.NetworkStatus)
				println("RAS Remote Status	: " + result.RemoteStatus)
				println("RAS Trigger      	: " + result.RemoteTrigger)
				println("RAS MPS Hostname 	: " + result.MPSHostname)
			}
		}
		if *amtInfoLanPtr {
			wired, _ := amt.GetLANInterfaceSettings(false)
			dataStruct["Wired Adapter"] = wired

			if !f.JsonOutput {
				println("---Wired Adapter---")
				println("DHCP Enabled 		: " + strconv.FormatBool(wired.DHCPEnabled))
				println("DHCP Mode    		: " + wired.DHCPMode)
				println("Link Status  		: " + wired.LinkStatus)
				println("IP Address   		: " + wired.IPAddress)
				println("MAC Address  		: " + wired.MACAddress)
			}

			wireless, _ := amt.GetLANInterfaceSettings(true)
			dataStruct["Wireless Adapter"] = wireless

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
			result, _ := amt.GetCertificateHashes()
			dataStruct["Certificate Hashes"] = result
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
