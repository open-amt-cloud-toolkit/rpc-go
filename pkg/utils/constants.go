/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

const (
	// ProjectName is the name of the executable
	ProjectName = "rpc"
	// ProjectVersion is the full version of this executable
	ProjectVersion  = "2.11.0"
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
	SubCommandChangePassword  = "changepassword"
	SubCommandSyncClock       = "syncclock"
	SubCommandSyncHostname    = "synchostname"
	SubCommandSyncIP          = "syncip"

	// Return Codes
	Success = 0

	// (1-99) General Errors

	// (1-19) Basic errors outside of Open AMT Cloud Toolkit
	IncorrectPermissions  = 1 // (not admin or sudo)
	HECIDriverNotDetected = 2
	AmtNotDetected        = 3
	AmtNotReady           = 4

	// (20-69) Input errors to RPC
	MissingOrIncorrectURL              = 20
	MissingOrIncorrectProfile          = 21
	ServerCerificateVerificationFailed = 22
	MissingOrIncorrectPassword         = 23
	MissingDNSSuffix                   = 24
	MissingHostname                    = 25
	MissingProxyAddressAndPort         = 26
	MissingOrIncorrectStaticIP         = 27
	IncorrectCommandLineParameters     = 28
	MissingOrIncorrectNetworkMask      = 29
	MissingOrIncorrectGateway          = 30
	MissingOrIncorrectPrimaryDNS       = 31
	MissingOrIncorrectSecondaryDNS     = 32
	InvalidParameterCombination        = 33

	// (70-99) Connection Errors
	RPSAuthenticationFailed         = 70
	AMTConnectionFailed             = 71
	OSNetworkInterfacesLookupFailed = 72

	// (100-149) Activation, and configuration errors
	AMTAuthenticationFailed        = 100
	WSMANMessageError              = 101
	ActivationFailed               = 102
	NetworkConfigurationFailed     = 103
	CIRAConfigurationFailed        = 104
	TLSConfigurationFailed         = 105
	WiFiConfigurationFailed        = 106
	AMTFeaturesConfigurationFailed = 107
	Ieee8021xConfigurationFailed   = 108
	UnableToDeactivate             = 109
	DeactivationFailed             = 110
	UnableToActivate               = 111
	WifiConfigurationWithWarnings  = 112

	// (150-199) Maintenance Errors
	SyncClockFailed      = 150
	SyncHostnameFailed   = 151
	SyncIpFailed         = 152
	ChangePasswordFailed = 153

	// (200-299) KPMU

	// (300-399) Redfish
)
