package config

type (
	Config struct {
		Password          string
		IEEE8021XSettings `yaml:"ieee801xConfig"`
		WifiConfigs       `yaml:"wifiConfigs"`
		Ieee8021xConfigs  `yaml:"ieee8021xConfigs"`
	}
	IEEE8021XSettings struct {
		Name                   string `yaml:"name"`
		AuthenticationMethod   int    `yaml:"authenticationMethod"`
		EncryptionMethod       int    `yaml:"encryptionMethod"`
		SSID                   string `yaml:"ssid"`
		Username               string `yaml:"username"`
		AuthenticationProtocol int    `yaml:"authenticationProtocol"`
		Priority               int    `yaml:"priority"`
		ClientCert             string `yaml:"clientCert"`
		CACert                 string `yaml:"caCert"`
		PrivateKey             string `yaml:"privateKey"`
	}
	WifiConfigs []struct {
		ProfileName          string `yaml:"profileName"`
		SSID                 string `yaml:"ssid"`
		Priority             int    `yaml:"priority"`
		AuthenticationMethod int    `yaml:"authenticationMethod"`
		EncryptionMethod     int    `yaml:"encryptionMethod"`
		PskPassphrase        string `yaml:"pskPassphrase"`
		Ieee8021xProfileName string `yaml:"ieee8021xProfileName"`
	}
	Ieee8021xConfigs []struct {
		ProfileName            string `yaml:"profileName"`
		Username               string `yaml:"username"`
		Password               string `yaml:"password"`
		AuthenticationProtocol int    `yaml:"authenticationProtocol"`
		ClientCert             string `yaml:"clientCert"`
		CACert                 string `yaml:"caCert"`
		PrivateKey             string `yaml:"privateKey"`
	}
)
