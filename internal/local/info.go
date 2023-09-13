package local

import (
	"encoding/json"
	"fmt"
	"os"
	"rpc/internal/amt"
	"rpc/pkg/utils"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) DisplayAMTInfo() utils.ReturnCode {
	dataStruct := make(map[string]interface{})

	amtCommand := amt.NewAMTCommand()
	if service.flags.AmtInfo.Ver {
		result, err := amtCommand.GetVersionDataFromME("AMT", service.flags.AMTTimeoutDuration)
		if err != nil {
			log.Error(err)
		}
		dataStruct["amt"] = result
		if !service.flags.JsonOutput {
			println("Version			: " + result)
		}
	}
	if service.flags.AmtInfo.Bld {
		result, err := amtCommand.GetVersionDataFromME("Build Number", service.flags.AMTTimeoutDuration)
		if err != nil {
			log.Error(err)
		}
		dataStruct["buildNumber"] = result

		if !service.flags.JsonOutput {
			println("Build Number		: " + result)
		}
	}
	if service.flags.AmtInfo.Sku {
		result, err := amtCommand.GetVersionDataFromME("Sku", service.flags.AMTTimeoutDuration)
		if err != nil {
			log.Error(err)
		}
		dataStruct["sku"] = result

		if !service.flags.JsonOutput {
			println("SKU			: " + result)
		}
	}
	if service.flags.AmtInfo.Ver && service.flags.AmtInfo.Sku {
		result := decodeAMT(dataStruct["amt"].(string), dataStruct["sku"].(string))
		dataStruct["features"] = strings.TrimSpace(result)
		if !service.flags.JsonOutput {
			println("Features		: " + result)
		}
	}
	if service.flags.AmtInfo.UUID {
		result, err := amtCommand.GetUUID()
		if err != nil {
			log.Error(err)
		}
		dataStruct["uuid"] = result

		if !service.flags.JsonOutput {
			println("UUID			: " + result)
		}
	}
	if service.flags.AmtInfo.Mode {
		result, err := amtCommand.GetControlMode()
		if err != nil {
			log.Error(err)
		}
		dataStruct["controlMode"] = utils.InterpretControlMode(result)

		if !service.flags.JsonOutput {
			println("Control Mode		: " + string(utils.InterpretControlMode(result)))
		}
	}
	if service.flags.AmtInfo.DNS {
		result, err := amtCommand.GetDNSSuffix()
		if err != nil {
			log.Error(err)
		}
		dataStruct["dnsSuffix"] = result

		if !service.flags.JsonOutput {
			println("DNS Suffix		: " + string(result))
		}
		result, err = amtCommand.GetOSDNSSuffix()
		if err != nil {
			log.Error(err)
		}
		dataStruct["dnsSuffixOS"] = result

		if !service.flags.JsonOutput {
			fmt.Println("DNS Suffix (OS)		: " + result)
		}
	}
	if service.flags.AmtInfo.Hostname {
		result, err := os.Hostname()
		if err != nil {
			log.Error(err)
		}
		dataStruct["hostnameOS"] = result
		if !service.flags.JsonOutput {
			println("Hostname (OS)		: " + string(result))
		}
	}

	if service.flags.AmtInfo.Ras {
		result, err := amtCommand.GetRemoteAccessConnectionStatus()
		if err != nil {
			log.Error(err)
		}
		dataStruct["ras"] = result

		if !service.flags.JsonOutput {
			println("RAS Network      	: " + result.NetworkStatus)
			println("RAS Remote Status	: " + result.RemoteStatus)
			println("RAS Trigger      	: " + result.RemoteTrigger)
			println("RAS MPS Hostname 	: " + result.MPSHostname)
		}
	}
	if service.flags.AmtInfo.Lan {
		wired, err := amtCommand.GetLANInterfaceSettings(false)
		if err != nil {
			log.Error(err)
		}
		dataStruct["wiredAdapter"] = wired

		if !service.flags.JsonOutput && wired.MACAddress != "00:00:00:00:00:00" {
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

		if !service.flags.JsonOutput {
			println("---Wireless Adapter---")
			println("DHCP Enabled 		: " + strconv.FormatBool(wireless.DHCPEnabled))
			println("DHCP Mode    		: " + wireless.DHCPMode)
			println("Link Status  		: " + wireless.LinkStatus)
			println("IP Address   		: " + wireless.IPAddress)
			println("MAC Address  		: " + wireless.MACAddress)
		}
	}
	if service.flags.AmtInfo.Cert {
		result, err := amtCommand.GetCertificateHashes()
		if err != nil {
			log.Error(err)
		}
		certs := make(map[string]interface{})
		for _, v := range result {
			certs[v.Name] = v
		}
		dataStruct["certificateHashes"] = certs
		if !service.flags.JsonOutput {
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
	if service.flags.JsonOutput {
		outBytes, err := json.MarshalIndent(dataStruct, "", "  ")
		output := string(outBytes)
		if err != nil {
			output = err.Error()
		}
		println(output)
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
