/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpc

import (
	"flag"
	"fmt"
	"os"
	"rpc/internal/amt"
	"rpc/pkg/utils"
	"strconv"
	"strings"
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
	SyncClock             bool
	amtInfoCommand        *flag.FlagSet
	amtActivateCommand    *flag.FlagSet
	amtDeactivateCommand  *flag.FlagSet
	amtMaintenanceCommand *flag.FlagSet
}

func NewFlags(args []string) *Flags {
	flags := &Flags{}
	flags.commandLineArgs = args
	flags.amtInfoCommand = flag.NewFlagSet("amtinfo", flag.ExitOnError)
	flags.amtActivateCommand = flag.NewFlagSet("activate", flag.ExitOnError)
	flags.amtDeactivateCommand = flag.NewFlagSet("deactivate", flag.ExitOnError)
	flags.amtMaintenanceCommand = flag.NewFlagSet("maintenance", flag.ExitOnError)
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
	passwordPtr := f.amtMaintenanceCommand.String("password", "", "AMT password")
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
		if *passwordPtr == "" {
			fmt.Println("Please enter AMT Password: ")
			var password string
			// Taking input from user
			_, err := fmt.Scanln(&password)
			if password == "" || err != nil {
				return false
			}
			*passwordPtr = password
		}
	}
	f.Command = "maintenance --synctime --password " + *passwordPtr
	return true
}
func (f *Flags) handleActivateCommand() bool {
	f.amtActivateCommand.StringVar(&f.DNS, "d", "", "dns suffix override")
	f.amtActivateCommand.StringVar(&f.Hostname, "h", "", "hostname override")
	f.amtActivateCommand.StringVar(&f.Profile, "profile", "", "name of the profile to use")
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
	passwordPtr := f.amtDeactivateCommand.String("password", "", "AMT password")
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
		if *passwordPtr == "" {
			fmt.Println("Please enter AMT Password: ")
			var password string
			// Taking input from user
			_, err := fmt.Scanln(&password)
			if password == "" || err != nil {
				return false
			}
			*passwordPtr = password
		}
		f.Command = "deactivate --password " + *passwordPtr
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
	if len(f.commandLineArgs) == 2 {
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
	amtInfoCommand.Parse(f.commandLineArgs[2:])

	if amtInfoCommand.Parsed() {
		amt := amt.Command{}
		if *amtInfoVerPtr {
			result, _ := amt.GetVersionDataFromME("AMT")
			println("Version			: " + result)
		}
		if *amtInfoBldPtr {
			result, _ := amt.GetVersionDataFromME("Build Number")
			println("Build Number		: " + result)
		}
		if *amtInfoSkuPtr {
			result, _ := amt.GetVersionDataFromME("Sku")
			println("SKU			: " + result)
		}
		if *amtInfoUUIDPtr {
			result, _ := amt.GetUUID()
			println("UUID			: " + result)
		}
		if *amtInfoModePtr {
			result, _ := amt.GetControlMode()
			println("Control Mode		: " + string(utils.InterpretControlMode(result)))
		}
		if *amtInfoDNSPtr {
			result, _ := amt.GetDNSSuffix()
			println("DNS Suffix		: " + string(result))
			result, _ = amt.GetOSDNSSuffix()
			fmt.Println("DNS Suffix (OS)		: " + result)
		}
		if *amtInfoHostnamePtr {
			result, _ := os.Hostname()
			println("Hostname (OS)		: " + string(result))
		}

		if *amtInfoRasPtr {
			result, _ := amt.GetRemoteAccessConnectionStatus()
			println("RAS Network      	: " + result.NetworkStatus)
			println("RAS Remote Status	: " + result.RemoteStatus)
			println("RAS Trigger      	: " + result.RemoteTrigger)
			println("RAS MPS Hostname 	: " + result.MPSHostname)
		}
		if *amtInfoLanPtr {
			wired, _ := amt.GetLANInterfaceSettings(false)
			println("---Wired Adapter---")
			println("DHCP Enabled 		: " + strconv.FormatBool(wired.DHCPEnabled))
			println("DHCP Mode    		: " + wired.DHCPMode)
			println("Link Status  		: " + wired.LinkStatus)
			println("IP Address   		: " + wired.IPAddress)
			println("MAC Address  		: " + wired.MACAddress)

			wireless, _ := amt.GetLANInterfaceSettings(true)
			println("---Wireless Adapter---")
			println("DHCP Enabled 		: " + strconv.FormatBool(wireless.DHCPEnabled))
			println("DHCP Mode    		: " + wireless.DHCPMode)
			println("Link Status  		: " + wireless.LinkStatus)
			println("IP Address   		: " + wireless.IPAddress)
			println("MAC Address  		: " + wireless.MACAddress)
		}
		if *amtInfoCertPtr {
			result, _ := amt.GetCertificateHashes()
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
}
