package flags

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
		if *amtInfoVerPtr && *amtInfoSkuPtr {
			result := decodeAMT(dataStruct["amt"].(string), dataStruct["sku"].(string))
			dataStruct["features"] = strings.TrimSpace(result)
			if !f.JsonOutput {
				println("Features		: " + result)
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

func decodeAMT(version, SKU string) string {
	amtParts := strings.Split(version, ".")
	if len(amtParts) <= 1 {
		return "Invalid AMT version format"
	}
	amtVer, err := strconv.ParseFloat(amtParts[0], 64)
	if err != nil {
		return "Invalid AMT version"
	}
	skuNum, err := strconv.ParseInt(SKU, 0, 64)
	if err != nil {
		return "Invalid SKU"
	}
	result := ""
	if amtVer <= 2.2 {
		switch skuNum {
		case 0:
			result += "AMT + ASF + iQST"
		case 1:
			result += "ASF + iQST"
		case 2:
			result += "iQST"
		default:
			result += "Unknown"
		}
	} else if amtVer < 5.0 {
		if skuNum&0x02 > 0 {
			result += "iQST "
		}
		if skuNum&0x04 > 0 {
			result += "ASF "
		}
		if skuNum&0x08 > 0 {
			result += "AMT"
		}
	} else {
		if skuNum&0x02 > 0 && amtVer < 7.0 {
			result += "iQST "
		}
		if skuNum&0x04 > 0 && amtVer < 6.0 {
			result += "ASF "
		}
		if skuNum&0x08 > 0 {
			result += "AMT Pro "
		}
		if skuNum&0x10 > 0 {
			result += "Intel Standard Manageability "
		}
		if skuNum&0x20 > 0 && amtVer < 6.0 {
			result += "TPM "
		}
		if skuNum&0x100 > 0 && amtVer < 6.0 {
			result += "Home IT "
		}
		if skuNum&0x400 > 0 && amtVer < 6.0 {
			result += "WOX "
		}
		if skuNum&0x2000 > 0 {
			result += "AT-p "
		}
		if skuNum&0x4000 > 0 {
			result += "Corporate "
		}
		if skuNum&0x8000 > 0 && amtVer < 8.0 {
			result += "L3 Mgt Upgrade"
		}
	}
	return result
}
