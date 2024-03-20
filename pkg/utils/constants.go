/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

type ReturnCode int

var ProjectVersion string = "Development Build"

const (
	// ProjectName is the name of the executable
	ProjectName = "rpc"
	// ProjectVersion is the full version of this executable
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

	SubCommandAddWifiSettings     = "addwifisettings"
	SubCommandAddEthernetSettings = "addethernetsettings"
	SubCommandEnableWifiPort      = "enablewifiport"
	SubCommandSetMEBx             = "mebx"
	SubCommandConfigureTLS        = "tls"
	SubCommandChangePassword      = "changepassword"
	SubCommandSyncDeviceInfo      = "syncdeviceinfo"
	SubCommandSyncClock           = "syncclock"
	SubCommandSyncHostname        = "synchostname"
	SubCommandSyncIP              = "syncip"
	SubCommandSetAMTFeatures      = "amtfeatures"

	// Return Codes
	Success ReturnCode = 0
)

// (1-99) General Errors

// (1-19) Basic errors outside of Open AMT Cloud Toolkit
var IncorrectPermissions = CustomError{Code: 1, Message: "IncorrectPermissions"}
var HECIDriverNotDetected = CustomError{Code: 2, Message: "HECIDriverNotDetected"}
var AmtNotDetected = CustomError{Code: 3, Message: "AmtNotDetected"}
var AmtNotReady = CustomError{Code: 4, Message: "AmtNotReady"}
var GenericFailure = CustomError{Code: 10, Message: "GenericFailure"}

// (20-69) Input errors to RPC
var MissingOrIncorrectURL = CustomError{Code: 20, Message: "MissingOrIncorrectURL"}
var MissingOrIncorrectProfile = CustomError{Code: 21, Message: "MissingOrIncorrectProfile"}
var ServerCerificateVerificationFailed = CustomError{Code: 22, Message: "ServerCerificateVerificationFailed"}
var MissingOrIncorrectPassword = CustomError{Code: 23, Message: "MissingOrIncorrectPassword"}
var MissingDNSSuffix = CustomError{Code: 24, Message: "MissingDNSSuffix"}
var MissingHostname = CustomError{Code: 25, Message: "MissingHostname"}
var MissingProxyAddressAndPort = CustomError{Code: 26, Message: "MissingProxyAddressAndPort"}
var MissingOrIncorrectStaticIP = CustomError{Code: 27, Message: "MissingOrIncorrectStaticIP"}
var IncorrectCommandLineParameters = CustomError{Code: 28, Message: "IncorrectCommandLineParameters"}
var MissingOrIncorrectNetworkMask = CustomError{Code: 29, Message: "MissingOrIncorrectNetworkMask"}
var MissingOrIncorrectGateway = CustomError{Code: 30, Message: "MissingOrIncorrectGateway"}
var MissingOrIncorrectPrimaryDNS = CustomError{Code: 31, Message: "MissingOrIncorrectPrimaryDNS"}
var MissingOrIncorrectSecondaryDNS = CustomError{Code: 32, Message: "MissingOrIncorrectSecondaryDNS"}
var InvalidParameterCombination = CustomError{Code: 33, Message: "InvalidParameterCombination"}
var FailedReadingConfiguration = CustomError{Code: 34, Message: "FailedReadingConfiguration"}
var MissingOrInvalidConfiguration = CustomError{Code: 35, Message: "MissingOrInvalidConfiguration"}
var InvalidUserInput = CustomError{Code: 36, Message: "InvalidUserInput"}
var InvalidUUID = CustomError{Code: 37, Message: "InvalidUUID"}
var PasswordsDoNotMatch = CustomError{Code: 38, Message: "PasswordsDoNotMatch"}

// (70-99) Connection Errors
var RPSAuthenticationFailed = CustomError{Code: 70, Message: "RPSAuthenticationFailed"}
var AMTConnectionFailed = CustomError{Code: 71, Message: "AMTConnectionFailed"}
var OSNetworkInterfacesLookupFailed = CustomError{Code: 72, Message: "OSNetworkInterfacesLookupFailed"}

// (100-149) Activation, and configuration errors
var AMTAuthenticationFailed = CustomError{Code: 100, Message: "AMTAuthenticationFailed"}
var WSMANMessageError = CustomError{Code: 101, Message: "WSMANMessageError"}
var ActivationFailed = CustomError{Code: 102, Message: "ActivationFailed"}
var NetworkConfigurationFailed = CustomError{Code: 103, Message: "NetworkConfigurationFailed"}
var CIRAConfigurationFailed = CustomError{Code: 104, Message: "CIRAConfigurationFailed"}
var TLSConfigurationFailed = CustomError{Code: 105, Message: "TLSConfigurationFailed"}
var WiFiConfigurationFailed = CustomError{Code: 106, Message: "WiFiConfigurationFailed"}
var AMTFeaturesConfigurationFailed = CustomError{Code: 107, Message: "AMTFeaturesConfigurationFailed"}
var Ieee8021xConfigurationFailed = CustomError{Code: 108, Message: "Ieee8021xConfigurationFailed"}
var UnableToDeactivate = CustomError{Code: 109, Message: "UnableToDeactivate"}
var DeactivationFailed = CustomError{Code: 110, Message: "DeactivationFailed"}
var UnableToActivate = CustomError{Code: 111, Message: "UnableToActivate"}
var WifiConfigurationWithWarnings = CustomError{Code: 112, Message: "WifiConfigurationWithWarnings"}
var UnmarshalMessageFailed = CustomError{Code: 113, Message: "UnmarshalMessageFailed"}
var DeleteWifiConfigFailed = CustomError{Code: 114, Message: "DeleteWifiConfigFailed"}
var MissingOrIncorrectWifiProfileName = CustomError{Code: 116, Message: "MissingOrIncorrectWifiProfileName"}
var MissingIeee8021xConfiguration = CustomError{Code: 117, Message: "MissingIeee8021xConfiguration"}
var SetMEBXPasswordFailed = CustomError{Code: 118, Message: "SetMEBXPasswordFailed"}
var UnableToConfigure = CustomError{Code: 111, Message: "UnableToconfigure"}

// (150-199) Maintenance Errors
var SyncClockFailed = CustomError{Code: 150, Message: "SyncClockFailed"}
var SyncHostnameFailed = CustomError{Code: 151, Message: "SyncHostnameFailed"}
var SyncIpFailed = CustomError{Code: 152, Message: "SyncIpFailed"}
var ChangePasswordFailed = CustomError{Code: 153, Message: "ChangePasswordFailed"}
var SyncDeviceInfoFailed = CustomError{Code: 154, Message: "SyncDeviceInfoFailed"}

// (200-299) KPMU

// (300-399) Redfish

// (1000 - 3000) Amt PT Status Code Block
var AmtPtStatusCodeBase = CustomError{Code: 1000, Message: "AmtPtStatusCodeBase"}
