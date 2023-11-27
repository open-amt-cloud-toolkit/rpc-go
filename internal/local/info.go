package local

import (
	"encoding/json"
	"fmt"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publicprivate"
	"os"
	"rpc/internal/amt"
	"rpc/pkg/utils"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type PrivateKeyPairReference struct {
	KeyPair         publicprivate.KeyPair
	AssociatedCerts []string
}

func (service *ProvisioningService) DisplayAMTInfo() utils.ReturnCode {
	dataStruct := make(map[string]interface{})
	cmd := service.amtCommand

	// UserCert precheck for provisioning mode and missing password
	// password is required for the local wsman connection but if device
	// has not been provisioned yet, then asking for the password is confusing
	// do this check first so prompts and errors messages happen before
	// any other displayed info
	if service.flags.AmtInfo.UserCert && service.flags.Password == "" {
		result, err := cmd.GetControlMode()
		if err != nil {
			log.Error(err)
			service.flags.AmtInfo.UserCert = false
		} else if result == 0 {
			fmt.Println("Device is in pre-provisioning mode. User certificates are not available")
			service.flags.AmtInfo.UserCert = false
		} else {
			if _, rc := service.flags.ReadPasswordFromUser(); rc != 0 {
				fmt.Println("Invalid Entry")
				return rc
			}
		}
	}

	if service.flags.AmtInfo.Ver {
		result, err := cmd.GetVersionDataFromME("AMT", service.flags.AMTTimeoutDuration)
		if err != nil {
			log.Error(err)
		}
		dataStruct["amt"] = result
		if !service.flags.JsonOutput {
			println("Version			: " + result)
		}
	}
	if service.flags.AmtInfo.Bld {
		result, err := cmd.GetVersionDataFromME("Build Number", service.flags.AMTTimeoutDuration)
		if err != nil {
			log.Error(err)
		}
		dataStruct["buildNumber"] = result

		if !service.flags.JsonOutput {
			println("Build Number		: " + result)
		}
	}
	if service.flags.AmtInfo.Sku {
		result, err := cmd.GetVersionDataFromME("Sku", service.flags.AMTTimeoutDuration)
		if err != nil {
			log.Error(err)
		}
		dataStruct["sku"] = result

		if !service.flags.JsonOutput {
			println("SKU			: " + result)
		}
	}
	if service.flags.AmtInfo.Ver && service.flags.AmtInfo.Sku {
		result := DecodeAMT(dataStruct["amt"].(string), dataStruct["sku"].(string))
		dataStruct["features"] = strings.TrimSpace(result)
		if !service.flags.JsonOutput {
			println("Features		: " + result)
		}
	}
	if service.flags.AmtInfo.UUID {
		result, err := cmd.GetUUID()
		if err != nil {
			log.Error(err)
		}
		dataStruct["uuid"] = result

		if !service.flags.JsonOutput {
			println("UUID			: " + result)
		}
	}
	if service.flags.AmtInfo.Mode {
		result, err := cmd.GetControlMode()
		if err != nil {
			log.Error(err)
		}
		dataStruct["controlMode"] = utils.InterpretControlMode(result)

		if !service.flags.JsonOutput {
			println("Control Mode		: " + string(utils.InterpretControlMode(result)))
		}
	}
	if service.flags.AmtInfo.OpState {
		result, err := cmd.GetChangeEnabled()
		if err != nil {
			log.Error(err)
		}
		if result.IsNewInterfaceVersion() {
			opStateValue := "disabled"
			if result.IsAMTEnabled() {
				opStateValue = "enabled"
			}
			dataStruct["operationalState"] = opStateValue
			if !service.flags.JsonOutput {
				println("Operational State	: " + opStateValue)
			}
		}
	}
	if service.flags.AmtInfo.DNS {
		result, err := cmd.GetDNSSuffix()
		if err != nil {
			log.Error(err)
		}
		dataStruct["dnsSuffix"] = result

		if !service.flags.JsonOutput {
			println("DNS Suffix		: " + string(result))
		}
		result, err = cmd.GetOSDNSSuffix()
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
		result, err := cmd.GetRemoteAccessConnectionStatus()
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
		wired, err := cmd.GetLANInterfaceSettings(false)
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

		wireless, err := cmd.GetLANInterfaceSettings(true)
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
		result, err := cmd.GetCertificateHashes()
		if err != nil {
			log.Error(err)
		}
		sysCertMap := map[string]amt.CertHashEntry{}
		for _, v := range result {
			sysCertMap[v.Name] = v
		}
		dataStruct["certificateHashes"] = sysCertMap
		if !service.flags.JsonOutput {
			if len(result) == 0 {
				fmt.Println("---No Certificate Hashes Found---")
			} else {
				fmt.Println("---Certificate Hashes---")
			}
			for k, v := range sysCertMap {
				fmt.Printf("%s", k)
				if v.IsDefault && v.IsActive {
					fmt.Printf("  (Default, Active)")
				} else if v.IsDefault {
					fmt.Printf("  (Default)")
				} else if v.IsActive {
					fmt.Printf("  (Active)")
				}
				fmt.Println()
				fmt.Println("   " + v.Algorithm + ": " + v.Hash)
			}
		}
	}
	if service.flags.AmtInfo.UserCert {
		service.setupWsmanClient("admin", service.flags.Password)
		var userCerts []publickey.PublicKeyCertificate
		service.GetPublicKeyCerts(&userCerts)
		userCertMap := map[string]publickey.PublicKeyCertificate{}
		for i := range userCerts {
			c := userCerts[i]
			name := GetTokenFromKeyValuePairs(c.Subject, "CN")
			// CN is not required by spec, but should work
			// just in case, provide something accurate
			if name == "" {
				name = c.InstanceID
			}
			userCertMap[name] = c
		}
		dataStruct["publicKeyCerts"] = userCertMap

		if !service.flags.JsonOutput {
			if len(userCertMap) == 0 {
				fmt.Println("---No Public Key Certs Found---")
			} else {
				fmt.Println("---Public Key Certs---")
			}
			for k, c := range userCertMap {
				fmt.Printf("%s", k)
				if c.TrustedRootCertficate && c.ReadOnlyCertificate {
					fmt.Printf("  (TrustedRoot, ReadOnly)")
				} else if c.TrustedRootCertficate {
					fmt.Printf("  (TrustedRoot)")
				} else if c.ReadOnlyCertificate {
					fmt.Printf("  (ReadOnly)")
				}
				fmt.Println()
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

func DecodeAMT(version, SKU string) string {
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
