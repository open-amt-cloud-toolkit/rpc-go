/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package config

type (
	Config struct {
		Password         string            `yaml:"password"`
		EthernetConfigs  EthernetConfig    `yaml:"wiredConfig"`
		WifiConfigs      []WifiConfig      `yaml:"wifiConfigs"`
		Ieee8021xConfigs []Ieee8021xConfig `yaml:"ieee8021xConfigs"`
		ACMSettings      ACMSettings       `yaml:"acmactivate"`
	}
	WifiConfig struct {
		ProfileName          string `yaml:"profileName"`
		SSID                 string `yaml:"ssid"`
		Priority             int    `yaml:"priority"`
		AuthenticationMethod int    `yaml:"authenticationMethod"`
		EncryptionMethod     int    `yaml:"encryptionMethod"`
		PskPassphrase        string `yaml:"pskPassphrase"`
		Ieee8021xProfileName string `yaml:"ieee8021xProfileName"`
	}
	EthernetConfig struct {
		DHCPEnabled  bool   `yaml:"dhcp"`
		Static       bool   `yaml:"static"`
		IpSync       bool   `yaml:"ipsync"`
		IpAddress    string `yaml:"ipaddress"`
		Subnetmask   string `yaml:"subnetmask"`
		Gateway      string `yaml:"gateway"`
		PrimaryDNS   string `yaml:"primarydns"`
		SecondaryDNS string `yaml:"secondarydns"`
	}
	SecretConfig struct {
		Secrets []Secret `yaml:"secrets"`
	}
	Secret struct {
		ProfileName   string `yaml:"profileName"`
		PskPassphrase string `yaml:"pskPassphrase"`
		PrivateKey    string `yaml:"privateKey"`
		Password      string `yaml:"password"`
	}
	Ieee8021xConfig struct {
		ProfileName            string `yaml:"profileName"`
		Username               string `yaml:"username"`
		Password               string `yaml:"password"`
		AuthenticationProtocol int    `yaml:"authenticationProtocol"`
		ClientCert             string `yaml:"clientCert"`
		CACert                 string `yaml:"caCert"`
		PrivateKey             string `yaml:"privateKey"`
	}

	ACMSettings struct {
		AMTPassword         string `yaml:"amtPassword"`
		ProvisioningCert    string `yaml:"provisioningCert"`
		ProvisioningCertPwd string `yaml:"provisioningCertPwd"`
	}
)
