package config

type (
	Config struct {
		Password         string            `yaml:"password"`
		WifiConfigs      []WifiConfig      `yaml:"wifiConfigs"`
		EthernetConfigs  []EthernetConfig  `yaml:"wifiConfigs"`
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
		ProfileName string `yaml:"profileName"`
		// SSID                 string `yaml:"ssid"`
		// Priority             int    `yaml:"priority"`
		AuthenticationMethod int `yaml:"authenticationMethod"`
		// EncryptionMethod     int    `yaml:"encryptionMethod"`
		// PskPassphrase        string `yaml:"pskPassphrase"`
		Ieee8021xProfileName string `yaml:"ieee8021xProfileName"`
		PXETimeout           int    `yaml:"pxeTimeout"` // ?
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
