/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

const (
	// ProjectName is the name of the executable
	ProjectName = "rpc"
	// ProjectVersion is the full version of this executable
	ProjectVersion  = "2.7.0"
	ProtocolVersion = "4.0.0"
	// ClientName is the name of the exectable
	ClientName = "RPC"

	// LMSAddress is used for determing what address to connect to LMS on
	LMSAddress = "localhost"
	// LMSPort is used for determining what port to connect to LMS on
	LMSPort = "16992"

	// MPSServerMaxLength is the max length of the servername
	MPSServerMaxLength = 256

	// Return Codes
	Success = 0

	// (1-99) General Errors

	// (1-19) Basic errors outside of Open AMT Cloud Toolkit
	IncorrectPermissions  = 1 // Incorrect permissions (not admin or sudo)
	HECIDriverNotDetected = 2 // HECI driver not detected
	AmtNotDetected        = 3 // AMT not detected
	AmtNotReady           = 4 // AMT not ready

	// (20-69) Input errors to RPC
	MissingOrIncorrectURL              = 20 // Missing or incorrect URL
	MissingOrIncorrectProfile          = 21 // Missing or incorrect profile
	ServerCerificateVerificationFailed = 22 // Server certificate verification failed
	MissingOrIncorrectPassword         = 23 // Missing or incorrect password
	MissingDNSSuffix                   = 24 // Missing DNS Suffix
	MissingHostname                    = 25 // Missing hostname
	MissingProxyAddressAndPort         = 26 // Missing proxy address and port
	MissingOrIncorrectStaticIP         = 27 // Missing static IP information
	IncorrectCommandLineParameters     = 28 // Incorrect number of command line parameters
	MissingOrIncorrectNetworkMask      = 29 // Missing or incorrect network mask
	MissingOrIncorrectGateway          = 30 // Missing or incorrect gateway
	MissingOrIncorrectPrimaryDNS       = 31 // Missing primary DNS Suffix
	MissingOrIncorrectSecondaryDNS     = 32 // Missing secondary DNS Suffix
	InvalidParameters                  = 33 // Invalid parameter combination

	// (70-99) Connection Errors
	RPSAuthenticationFailed         = 70 // RPS authentication failed
	AMTConnectionFailed             = 71
	OSNetworkInterfacesLookupFailed = 72

	// (100-149) Activation, and configuration errors
	AMTAuthenticationFailed         = 100 // AMT authentication failed
	WSMANMessageError               = 101 // WSMAN message error
	ActivationFailed                = 102 // Activation failed
	NetworkConfigurationFailed      = 103 // Network configuration failed
	CIRAConfigurationFailed         = 104 // CIRA configuration failed
	TLSConfigurationFailed          = 105 // TLS configuration failed
	WiFiConfigurationFailed         = 106 // WiFi configuration failed
	AMTConfigurationFailed          = 107 // AMT features configuration failed
	EightZeroTwoConfigurationFailed = 108 // 802.1x configuration failed
	UnableToDeactivate              = 109 // Device is not in CCM mode
	DeactivationFailed              = 110 // Deactivation Failed

	// (150-199) Maintenance Errors
	ClockSyncFailed    = 150 // Clock sync failed
	HostnameSyncFailed = 151 // Hostname sync failed
	NetworkSyncFailed  = 152 // Network sync failed

	// (200-299) KPMU

	// (300-399) Redfish
)
