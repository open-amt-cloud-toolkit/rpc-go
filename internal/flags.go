/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpc

import (
	"flag"
	"fmt"
	"os"
	"rpc/pkg/utils"
	"strconv"
	"strings"
)

// Flags holds data received from the command line
type Flags struct {
	URL           string
	DNS           string
	Proxy         string
	Command       string
	SkipCertCheck bool
	Verbose       bool
}

// ParseFlags is used for understanding the command line flags
func ParseFlags() (Flags, error) {

	f := Flags{}

	//required
	urlPtr := flag.String("u", "", "websocker server address")
	cmdPtr := flag.String("c", "", "server command")
	//optional
	proxyPtr := flag.String("p", "", "proxy address and port")
	dnsPtr := flag.String("d", "", "dns suffix override")
	verbosePtr := flag.Bool("v", false, "verbose output")
	skipCertPtr := flag.Bool("n", false, "skip websocket server certificate verification")
	//informational
	versionPtr := flag.Bool("version", false, "version of rpc")

	amtInfoCommand := flag.NewFlagSet("amtinfo", flag.ExitOnError)

	//amtinfoStr := flag.String("", "", "AMT info on an <item>")

	flag.Parse()

	if *verbosePtr {
		f.Verbose = true
	}
	if *skipCertPtr {
		f.SkipCertCheck = true
	}
	if *versionPtr {
		println(strings.ToUpper(ProjectName))
		println("Protocol " + ProtocolVersion)
		os.Exit(1)
	}

	result, err := Initialize()
	if result == false || err != nil {
		println("Unable to launch application. Please ensure that Intel ME is present, the MEI driver is installed and that this application is run with administrator or root privileges.")
		os.Exit(1)
	}

	handleAMTInfo(amtInfoCommand)

	if *urlPtr == "" || *cmdPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	f.URL = *urlPtr
	f.Command = *cmdPtr

	if *dnsPtr != "" {
		f.DNS = *dnsPtr
	}
	if *proxyPtr != "" {
		f.Proxy = *proxyPtr
	}
	return f, nil
}

func handleAMTInfo(amtInfoCommand *flag.FlagSet) {

	amtInfoAllPtr := amtInfoCommand.Bool("all", false, "All AMT Info")
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

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "amtinfo":
			amtInfoCommand.Parse(os.Args[2:])
		}

		if amtInfoCommand.Parsed() {
			if *amtInfoAllPtr {
				*amtInfoVerPtr = true
				*amtInfoBldPtr = true
				*amtInfoSkuPtr = true
				*amtInfoUUIDPtr = true
				*amtInfoModePtr = true
				*amtInfoDNSPtr = true
				*amtInfoCertPtr = true
				*amtInfoRasPtr = true
				*amtInfoLanPtr = true
				*amtInfoHostnamePtr = true
			}

			if *amtInfoVerPtr {
				result, _ := GetVersionDataFromME("AMT")
				println("Version			: " + result)
			}
			if *amtInfoBldPtr {
				result, _ := GetVersionDataFromME("Build Number")
				println("Build Number		: " + result)
			}
			if *amtInfoSkuPtr {
				result, _ := GetVersionDataFromME("Sku")
				println("SKU			: " + result)
			}
			if *amtInfoUUIDPtr {
				result, _ := GetUUID()
				println("UUID			: " + result)
			}
			if *amtInfoModePtr {
				result, _ := GetControlMode()
				println("Control Mode		: " + string(utils.InterpretControlMode(result)))
			}
			if *amtInfoDNSPtr {
				result, _ := GetDNSSuffix()
				println("DNS Suffix		: " + string(result))
				result, _ = GetOSDNSSuffix()
				fmt.Println("DNS Suffix (OS)		: " + result)
			}
			if *amtInfoHostnamePtr {
				result, _ := os.Hostname()
				println("Hostname (OS)		: " + string(result))
			}

			if *amtInfoRasPtr {
				result, _ := GetRemoteAccessConnectionStatus()
				println("RAS Network      	: " + result.NetworkStatus)
				println("RAS Remote Status	: " + result.RemoteStatus)
				println("RAS Trigger      	: " + result.RemoteTrigger)
				println("RAS MPS Hostname 	: " + result.MPSHostname)
			}
			if *amtInfoLanPtr {
				wired, _ := GetLANInterfaceSettings(false)
				println("---Wired Adapter---")
				println("DHCP Enabled 		: " + strconv.FormatBool(wired.DHCPEnabled))
				println("DHCP Mode    		: " + wired.DHCPMode)
				println("Link Status  		: " + wired.LinkStatus)
				println("IP Address   		: " + wired.IPAddress)
				println("MAC Address  		: " + wired.MACAddress)

				wireless, _ := GetLANInterfaceSettings(true)
				println("---Wireless Adapter---")
				println("DHCP Enabled 		: " + strconv.FormatBool(wireless.DHCPEnabled))
				println("DHCP Mode    		: " + wireless.DHCPMode)
				println("Link Status  		: " + wireless.LinkStatus)
				println("IP Address   		: " + wireless.IPAddress)
				println("MAC Address  		: " + wireless.MACAddress)
			}
			if *amtInfoCertPtr {
				result, _ := GetCertificateHashes()
				println("Certificate Hashes	:")
				for _, v := range result {

					print(strings.Trim(v.Name, "\xab") + " (")
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
			// else {
			// 	amtInfoCommand.PrintDefaults()
			// }
			os.Exit(1)
		}
	}
}
