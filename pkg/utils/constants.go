/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

type ReturnCode int

const (
	// ProjectName is the name of the executable
	ProjectName = "rpc"
	// ProjectVersion is the full version of this executable
	ProjectVersion  = "2.24.4"
	ProtocolVersion = "4.0.0"
	// ClientName is the name of the exectable
	ClientName = "RPC"

	// LMSAddress is used for determing what address to connect to LMS on
	LMSAddress = "localhost"
	// LMSPort is used for determining what port to connect to LMS on
	LMSPort = "16992"

	// MPSServerMaxLength is the max length of the servername
	MPSServerMaxLength = 256

	CommandActivate    = "activate"
	CommandAMTInfo     = "amtinfo"
	CommandDeactivate  = "deactivate"
	CommandMaintenance = "maintenance"
	CommandVersion     = "version"
	CommandConfigure   = "configure"

	SubCommandAddWifiSettings = "addwifisettings"
	SubCommandEnableWifiPort  = "enablewifiport"
	SubCommandChangePassword  = "changepassword"
	SubCommandSyncDeviceInfo  = "syncdeviceinfo"
	SubCommandSyncClock       = "syncclock"
	SubCommandSyncHostname    = "synchostname"
	SubCommandSyncIP          = "syncip"

	// Return Codes
	Success ReturnCode = 0

	// (1-99) General Errors

	// (1-19) Basic errors outside of Open AMT Cloud Toolkit
	IncorrectPermissions  ReturnCode = 1 // (not admin or sudo)
	HECIDriverNotDetected ReturnCode = 2
	AmtNotDetected        ReturnCode = 3
	AmtNotReady           ReturnCode = 4

	// (20-69) Input errors to RPC
	MissingOrIncorrectURL              ReturnCode = 20
	MissingOrIncorrectProfile          ReturnCode = 21
	ServerCerificateVerificationFailed ReturnCode = 22
	MissingOrIncorrectPassword         ReturnCode = 23
	MissingDNSSuffix                   ReturnCode = 24
	MissingHostname                    ReturnCode = 25
	MissingProxyAddressAndPort         ReturnCode = 26
	MissingOrIncorrectStaticIP         ReturnCode = 27
	IncorrectCommandLineParameters     ReturnCode = 28
	MissingOrIncorrectNetworkMask      ReturnCode = 29
	MissingOrIncorrectGateway          ReturnCode = 30
	MissingOrIncorrectPrimaryDNS       ReturnCode = 31
	MissingOrIncorrectSecondaryDNS     ReturnCode = 32
	InvalidParameterCombination        ReturnCode = 33
	FailedReadingConfiguration         ReturnCode = 34
	MissingOrInvalidConfiguration      ReturnCode = 35
	InvalidUserInput                   ReturnCode = 36
	InvalidUUID                        ReturnCode = 37

	// (70-99) Connection Errors
	RPSAuthenticationFailed         ReturnCode = 70
	AMTConnectionFailed             ReturnCode = 71
	OSNetworkInterfacesLookupFailed ReturnCode = 72

	// (100-149) Activation, and configuration errors
	AMTAuthenticationFailed           ReturnCode = 100
	WSMANMessageError                 ReturnCode = 101
	ActivationFailed                  ReturnCode = 102
	NetworkConfigurationFailed        ReturnCode = 103
	CIRAConfigurationFailed           ReturnCode = 104
	TLSConfigurationFailed            ReturnCode = 105
	WiFiConfigurationFailed           ReturnCode = 106
	AMTFeaturesConfigurationFailed    ReturnCode = 107
	Ieee8021xConfigurationFailed      ReturnCode = 108
	UnableToDeactivate                ReturnCode = 109
	DeactivationFailed                ReturnCode = 110
	UnableToActivate                  ReturnCode = 111
	WifiConfigurationWithWarnings     ReturnCode = 112
	UnmarshalMessageFailed            ReturnCode = 113
	DeleteWifiConfigFailed            ReturnCode = 114
	MissingOrIncorrectWifiProfileName ReturnCode = 116
	MissingIeee8021xConfiguration     ReturnCode = 117

	// (150-199) Maintenance Errors
	SyncClockFailed      ReturnCode = 150
	SyncHostnameFailed   ReturnCode = 151
	SyncIpFailed         ReturnCode = 152
	ChangePasswordFailed ReturnCode = 153
	SyncDeviceInfoFailed ReturnCode = 154

	// (200-299) KPMU

	// (300-399) Redfish

	// (1000 - 3000) Amt PT Status Code Block
	AmtPtStatusCodeBase ReturnCode = 1000
)
