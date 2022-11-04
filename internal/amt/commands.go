/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package amt is used for executing calls against the PTHI/HECI driver and transforming the data to be returned
package amt

import (
	"errors"
	"fmt"
	"net"
	"os"
	"rpc/pkg/pthi"
	"rpc/pkg/utils"
	"strconv"
	"strings"
)

//TODO: Ensure pointers are freed properly throughout this file

// UnicodeString ...
type UnicodeString struct {
	Length uint16
	String [20]uint8 //[UNICODE_STRING_LEN]
}

// VersionType ...
type VersionType struct {
	Description UnicodeString
	Version     UnicodeString
}

// CodeVersions ...
type CodeVersions struct {
	BiosVersion   [65]uint8 //[BIOS_VERSION_LEN]
	VersionsCount uint32
	Versions      [50]VersionType //[VERSIONS_NUMBER]
}

// InterfaceSettings ...
type InterfaceSettings struct {
	IsEnabled   bool   `json:"isEnable"`
	LinkStatus  string `json:"linkStatus"`
	DHCPEnabled bool   `json:"dhcpEnabled"`
	DHCPMode    string `json:"dhcpMode"`
	IPAddress   string `json:"ipAddress"` //net.IP
	MACAddress  string `json:"macAddress"`
}

// RemoteAccessStatus holds connect status information
type RemoteAccessStatus struct {
	NetworkStatus string `json:"networkStatus"`
	RemoteStatus  string `json:"remoteStatus"`
	RemoteTrigger string `json:"remoteTrigger"`
	MPSHostname   string `json:"mpsHostname"`
}

// CertHashEntry is the GO struct for holding Cert Hash Entries
type CertHashEntry struct {
	Hash      string
	Name      string
	Algorithm string
	IsActive  bool
	IsDefault bool
}

// LocalSystemAccount holds username and password
type LocalSystemAccount struct {
	Username string
	Password string
}

type Interface interface {
	Initialize() (bool, error)
	GetVersionDataFromME(key string) (string, error)
	GetUUID() (string, error)
	GetControlMode() (int, error)
	GetOSDNSSuffix() (string, error)
	GetDNSSuffix() (string, error)
	GetCertificateHashes() ([]CertHashEntry, error)
	GetRemoteAccessConnectionStatus() (RemoteAccessStatus, error)
	GetLANInterfaceSettings(useWireless bool) (InterfaceSettings, error)
	GetLocalSystemAccount() (LocalSystemAccount, error)
}

func ANSI2String(ansi pthi.AMTANSIString) string {
	output := ""
	for i := 0; i < int(ansi.Length); i++ {
		output = output + string(ansi.Buffer[i])
	}

	return output
}

type AMTCommand struct {
	PTHI pthi.Interface
}

func NewAMTCommand() AMTCommand {
	return AMTCommand{
		PTHI: pthi.NewCommand(),
	}
}

// Initialize determines if rpc is able to initialize the heci driver
func (amt AMTCommand) Initialize() (bool, error) {
	// initialize HECI interface
	err := amt.PTHI.Open(false)

	if err != nil {
		if err.Error() == "The handle is invalid." {
			return false, errors.New("AMT not found: MEI/driver is missing or the call to the HECI driver failed")
		}
		return false, errors.New("unable to initialize")
	}

	defer amt.PTHI.Close()
	return true, nil
}

// GetVersionDataFromME ...
func (amt AMTCommand) GetVersionDataFromME(key string) (string, error) {

	err := amt.PTHI.Open(false)
	if err != nil {
		return "", err
	}

	result, err := amt.PTHI.GetCodeVersions()
	amt.PTHI.Close()
	if err != nil {
		return "", err
	}

	for i := 0; i < int(result.CodeVersion.VersionsCount); i++ {
		if string(result.CodeVersion.Versions[i].Description.String[:result.CodeVersion.Versions[i].Description.Length]) == key {
			return strings.Replace(string(result.CodeVersion.Versions[i].Version.String[:]), "\u0000", "", -1), nil
		}
	}

	return "", errors.New(key + " Not Found")
}

// GetUUID ...
func (amt AMTCommand) GetUUID() (string, error) {
	err := amt.PTHI.Open(false)
	if err != nil {
		return "", err
	}
	defer amt.PTHI.Close()
	result, err := amt.PTHI.GetUUID()
	if err != nil {
		return "", err
	}

	var hexValues [16]string

	for i := 0; i < 16; i++ {
		hexValues[i] = fmt.Sprintf("%02x", int(result[i]))
	}

	uuidStr := hexValues[3] + hexValues[2] + hexValues[1] + hexValues[0] + "-" +
		hexValues[5] + hexValues[4] + "-" +
		hexValues[7] + hexValues[6] + "-" +
		hexValues[8] + hexValues[9] + "-" +
		hexValues[10] + hexValues[11] + hexValues[12] + hexValues[13] + hexValues[14] + hexValues[15]
	return uuidStr, nil

}

// GetControlMode ...
func (amt AMTCommand) GetControlMode() (int, error) {
	err := amt.PTHI.Open(false)
	if err != nil {
		return -1, err
	}
	defer amt.PTHI.Close()
	result, err := amt.PTHI.GetControlMode()
	if err != nil {
		return -1, err
	}

	return result, nil
}

// GetDNSSuffix ...
func (amt AMTCommand) GetOSDNSSuffix() (string, error) {
	lanResult, _ := amt.GetLANInterfaceSettings(false)
	ifaces, _ := net.Interfaces()
	for _, v := range ifaces {
		if v.HardwareAddr.String() == lanResult.MACAddress {
			addrs, _ := v.Addrs()
			for _, a := range addrs {
				networkIP, ok := a.(*net.IPNet)
				if ok && !networkIP.IP.IsLoopback() && networkIP.IP.To4() != nil {
					ip := networkIP.IP.String()
					suffix, _ := net.LookupAddr(ip)
					if len(suffix) > 0 {
						hostname, _ := os.Hostname()
						dnsSuffix := strings.Trim(suffix[0], hostname)
						dnsSuffix = strings.TrimLeft(dnsSuffix, ".")
						dnsSuffix = strings.TrimRight(dnsSuffix, ".")
						return dnsSuffix, nil
					}
					return "", nil
				}
			}
		}
	}
	return "", nil
}

func (amt AMTCommand) GetDNSSuffix() (string, error) {
	err := amt.PTHI.Open(false)
	if err != nil {
		return "", err
	}
	defer amt.PTHI.Close()
	result, err := amt.PTHI.GetDNSSuffix()
	if err != nil {
		return "", err
	}

	return result, nil
}

func (amt AMTCommand) GetCertificateHashes() ([]CertHashEntry, error) {
	err := amt.PTHI.Open(false)
	amtEntryList := []CertHashEntry{}
	if err != nil {
		return amtEntryList, err
	}
	defer amt.PTHI.Close()
	pthiEntryList, err := amt.PTHI.GetCertificateHashes(pthi.AMTHashHandles{})
	if err != nil {
		return amtEntryList, err
	}

	// Convert pthi results to amt results
	for _, pthiEntry := range pthiEntryList {

		hashSize, algo := utils.InterpretHashAlgorithm(int(pthiEntry.HashAlgorithm))

		hashString := ""
		for i := 0; i < hashSize; i++ {
			hashString = hashString + fmt.Sprintf("%02x", int(pthiEntry.CertificateHash[i]))
		}

		amtEntry := CertHashEntry{
			Hash:      hashString,
			Name:      ANSI2String(pthiEntry.Name),
			Algorithm: algo,
			IsActive:  pthiEntry.IsActive > 0,
			IsDefault: pthiEntry.IsDefault > 0,
		}

		amtEntryList = append(amtEntryList, amtEntry)
	}

	return amtEntryList, nil
}

func (amt AMTCommand) GetRemoteAccessConnectionStatus() (RemoteAccessStatus, error) {
	err := amt.PTHI.Open(false)
	emptyRAStatus := RemoteAccessStatus{}
	if err != nil {
		return emptyRAStatus, err
	}
	defer amt.PTHI.Close()
	result, err := amt.PTHI.GetRemoteAccessConnectionStatus()
	if err != nil {
		return emptyRAStatus, err
	}

	RAStatus := RemoteAccessStatus{
		NetworkStatus: utils.InterpretAMTNetworkConnectionStatus(int(result.NetworkStatus)),
		RemoteStatus:  utils.InterpretRemoteAccessConnectionStatus(int(result.RemoteStatus)),
		RemoteTrigger: utils.InterpretRemoteAccessTrigger(int(result.RemoteTrigger)),
		MPSHostname:   ANSI2String(result.MPSHostname),
	}

	return RAStatus, nil
}

func (amt AMTCommand) GetLANInterfaceSettings(useWireless bool) (InterfaceSettings, error) {
	err := amt.PTHI.Open(false)
	emptySettings := InterfaceSettings{}
	if err != nil {
		return emptySettings, err
	}
	defer amt.PTHI.Close()
	result, err := amt.PTHI.GetLANInterfaceSettings(useWireless)
	if err != nil {
		return emptySettings, err
	}

	settings := InterfaceSettings{
		IPAddress:   "0.0.0.0",
		IsEnabled:   result.Enabled == 1,
		DHCPEnabled: result.DhcpEnabled == 1,
		LinkStatus:  "down",
		DHCPMode:    "passive",
	}

	if result.LinkStatus == 1 {
		settings.LinkStatus = "up"
	}

	if result.DhcpIPMode == 1 {
		settings.DHCPMode = "active"
	}

	part1 := result.Ipv4Address >> 24 & 0xff
	part2 := result.Ipv4Address >> 16 & 0xff
	part3 := result.Ipv4Address >> 8 & 0xff
	part4 := result.Ipv4Address & 0xff

	settings.IPAddress = strconv.Itoa(int(part1)) + "." + strconv.Itoa(int(part2)) + "." + strconv.Itoa(int(part3)) + "." + strconv.Itoa(int(part4))

	macPart0 := fmt.Sprintf("%02x", int(result.MacAddress[0]))
	macPart1 := fmt.Sprintf("%02x", int(result.MacAddress[1]))
	macPart2 := fmt.Sprintf("%02x", int(result.MacAddress[2]))
	macPart3 := fmt.Sprintf("%02x", int(result.MacAddress[3]))
	macPart4 := fmt.Sprintf("%02x", int(result.MacAddress[4]))
	macPart5 := fmt.Sprintf("%02x", int(result.MacAddress[5]))
	settings.MACAddress = macPart0 + ":" + macPart1 + ":" + macPart2 + ":" + macPart3 + ":" + macPart4 + ":" + macPart5

	return settings, nil
}

func (amt AMTCommand) GetLocalSystemAccount() (LocalSystemAccount, error) {
	err := amt.PTHI.Open(false)
	emptySystemAccount := LocalSystemAccount{}
	if err != nil {
		return emptySystemAccount, err
	}
	defer amt.PTHI.Close()
	result, err := amt.PTHI.GetLocalSystemAccount()
	if err != nil {
		return emptySystemAccount, err
	}

	username := ""
	for i := 0; i < len(result.Account.Username); i++ {
		if string(result.Account.Username[i]) != "\x00" {
			username = username + string(result.Account.Username[i])
		}
	}

	password := ""
	for i := 0; i < len(result.Account.Password); i++ {
		if string(result.Account.Password[i]) != "\x00" {
			password = password + string(result.Account.Password[i])
		}
	}

	lsa := LocalSystemAccount{
		Username: username,
		Password: password,
	}

	return lsa, nil
}
