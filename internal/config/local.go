package config

type (
	Config struct {
		Password          string
		IEEE8021XSettings `yaml:"ieee801xConfig"`
		WifiConfigs       `yaml:"wifiConfigs"`
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
		Priority               int    `yaml:"priority"`
		ProfileName            string `yaml:"profileName"`
		AuthenticationMethod   int    `yaml:"authenticationMethod"`
		EncryptionMethod       int    `yaml:"encryptionMethod"`
		SSID                   string `yaml:"ssid"`
		PskPassphrase          string `yaml:"pskPassphrase"`
		Username               string `yaml:"username"`
		Password               string `yaml:"password"`
		AuthenticationProtocol int    `yaml:"authenticationProtocol"`
		ClientCert             string `yaml:"clientCert"`
		CACert                 string `yaml:"caCert"`
		PrivateKey             string `yaml:"privateKey"`
	}
)
