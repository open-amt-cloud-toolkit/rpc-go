/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"rpc/internal/amt"
	"rpc/pkg/utils"
	"strconv"
	"strings"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/sirupsen/logrus"
)

type PrivateKeyPairReference struct {
	KeyPair         publicprivate.KeyPair
	AssociatedCerts []string
}

func (service *ProvisioningService) DisplayAMTInfo() (err error) {
	dataStruct := make(map[string]interface{})
	cmd := service.amtCommand
	cmd.StopTLSActivation()
	// UserCert precheck for provisioning mode and missing password
	// password is required for the local wsman connection but if device
	// has not been provisioned yet, then asking for the password is confusing
	// do this check first so prompts and errors messages happen before
	// any other displayed info
	if service.flags.AmtInfo.UserCert && service.flags.Password == "" {
		result, err := cmd.GetControlMode()
		if err != nil {
			logrus.Error(err)
			service.flags.AmtInfo.UserCert = false
		} else if result == 0 {
			logrus.Warn("Device is in pre-provisioning mode. User certificates are not available")
			service.flags.AmtInfo.UserCert = false
		} else {
			if err := service.flags.ReadPasswordFromUser(); err != nil {
				fmt.Println("Invalid Entry")
				return err
			}
		}
	}

	if service.flags.AmtInfo.Ver {
		result, err := cmd.GetVersionDataFromME("AMT", service.flags.AMTTimeoutDuration)
		if err != nil {
			logrus.Error(err)
		}
		dataStruct["amt"] = result
		service.PrintOutput("Version			: " + result)
	}
	if service.flags.AmtInfo.Bld {
		result, err := cmd.GetVersionDataFromME("Build Number", service.flags.AMTTimeoutDuration)
		if err != nil {
			logrus.Error(err)
		}

		dataStruct["buildNumber"] = result
		service.PrintOutput("Build Number		: " + result)
	}
	if service.flags.AmtInfo.Sku {
		result, err := cmd.GetVersionDataFromME("Sku", service.flags.AMTTimeoutDuration)
		if err != nil {
			logrus.Error(err)
		}

		dataStruct["sku"] = result
		service.PrintOutput("SKU			: " + result)
	}
	if service.flags.AmtInfo.Ver && service.flags.AmtInfo.Sku {
		result := DecodeAMT(dataStruct["amt"].(string), dataStruct["sku"].(string))

		dataStruct["features"] = strings.TrimSpace(result)
		service.PrintOutput("Features		: " + result)
	}
	if service.flags.AmtInfo.UUID {
		result, err := cmd.GetUUID()
		if err != nil {
			logrus.Error(err)
		}

		dataStruct["uuid"] = result
		service.PrintOutput("UUID			: " + result)
	}
	if service.flags.AmtInfo.Mode {
		result, err := cmd.GetControlMode()
		if err != nil {
			logrus.Error(err)
		}
		dataStruct["controlMode"] = utils.InterpretControlMode(result)
		if !service.flags.JsonOutput {
			println("Control Mode		: " + string(utils.InterpretControlMode(result)))
		}
		if result == 0 {
			result, err = cmd.GetProvisioningState()
			if err != nil {
				logrus.Error(err)
			}
			dataStruct["provisioningState"] = utils.InterpretProvisioningState(result)
			if !service.flags.JsonOutput {
				println("Provisioning State	: " + string(utils.InterpretProvisioningState(result)))
			}
		}
	}
	if service.flags.AmtInfo.OpState {
		result, err := cmd.GetChangeEnabled()
		if err != nil {
			logrus.Error(err)
		}
		if result.IsNewInterfaceVersion() {
			opStateValue := "disabled"
			if result.IsAMTEnabled() {
				opStateValue = "enabled"
			}

			dataStruct["operationalState"] = opStateValue
			service.PrintOutput("Operational State	: " + opStateValue)
		}
	}
	if service.flags.AmtInfo.DNS {
		result, err := cmd.GetDNSSuffix()
		if err != nil {
			logrus.Error(err)
		}
		dataStruct["dnsSuffix"] = result
		service.PrintOutput("DNS Suffix		: " + string(result))

		result, err = cmd.GetOSDNSSuffix()
		if err != nil {
			logrus.Error(err)
		}

		dataStruct["dnsSuffixOS"] = result
		service.PrintOutput("DNS Suffix (OS)		: " + result)
	}
	if service.flags.AmtInfo.Hostname {
		result, err := os.Hostname()
		if err != nil {
			logrus.Error(err)
		}
		dataStruct["hostnameOS"] = result
		service.PrintOutput("Hostname (OS)		: " + string(result))
	}

	if service.flags.AmtInfo.Ras {
		result, err := cmd.GetRemoteAccessConnectionStatus()
		if err != nil {
			logrus.Error(err)
		}
		dataStruct["ras"] = result

		service.PrintOutput("RAS Network      	: " + result.NetworkStatus)
		service.PrintOutput("RAS Remote Status	: " + result.RemoteStatus)
		service.PrintOutput("RAS Trigger      	: " + result.RemoteTrigger)
		service.PrintOutput("RAS MPS Hostname 	: " + result.MPSHostname)

	}
	if service.flags.AmtInfo.Lan {
		wired, err := cmd.GetLANInterfaceSettings(false)
		if err != nil {
			logrus.Error(err)
		}
		dataStruct["wiredAdapter"] = wired

		if wired.MACAddress != "00:00:00:00:00:00" {
			service.PrintOutput("---Wired Adapter---")
			service.PrintOutput("DHCP Enabled 		: " + strconv.FormatBool(wired.DHCPEnabled))
			service.PrintOutput("DHCP Mode    		: " + wired.DHCPMode)
			service.PrintOutput("Link Status  		: " + wired.LinkStatus)
			service.PrintOutput("IP Address   		: " + wired.IPAddress)
			service.PrintOutput("MAC Address  		: " + wired.MACAddress)
		}

		wireless, err := cmd.GetLANInterfaceSettings(true)
		if err != nil {
			logrus.Error(err)
		}
		dataStruct["wirelessAdapter"] = wireless

		service.PrintOutput("---Wireless Adapter---")
		service.PrintOutput("DHCP Enabled 		: " + strconv.FormatBool(wireless.DHCPEnabled))
		service.PrintOutput("DHCP Mode    		: " + wireless.DHCPMode)
		service.PrintOutput("Link Status  		: " + wireless.LinkStatus)
		service.PrintOutput("IP Address   		: " + wireless.IPAddress)
		service.PrintOutput("MAC Address  		: " + wireless.MACAddress)

	}
	if service.flags.AmtInfo.Cert {
		result, err := cmd.GetCertificateHashes()
		if err != nil {
			logrus.Error(err)
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
		service.interfacedWsmanMessage.SetupWsmanClient("admin", service.flags.Password, logrus.GetLevel() == logrus.TraceLevel, []tls.Certificate{service.flags.RPCTLSActivationCertificate.TlsCert})
		userCerts, _ := service.interfacedWsmanMessage.GetPublicKeyCerts()
		userCertMap := map[string]publickey.PublicKeyCertificateResponse{}
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
				if c.TrustedRootCertificate && c.ReadOnlyCertificate {
					fmt.Printf("  (TrustedRoot, ReadOnly)")
				} else if c.TrustedRootCertificate {
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
		fmt.Println(output)
	}
	return nil
}
func (service *ProvisioningService) PrintOutput(message string) {
	if !service.flags.JsonOutput {
		fmt.Println(message)
	}
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
