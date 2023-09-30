package commands

type (
	AppConfig struct {
		Password         string            `yaml:"password"`
		WifiConfigs      []WifiConfig      `mapstructure:"wifiConfigs"`
		Ieee8021xConfigs []Ieee8021xConfig `mapstructure:"ieee8021xConfigs"`
		ACMSettings      `mapstructure:"acmactivate"`
	}

	WifiConfig struct {
		ProfileName          string `mapstructure:"profileName"`
		SSID                 string `mapstructure:"ssid"`
		Priority             int    `mapstructure:"priority"`
		AuthenticationMethod int    `mapstructure:"authenticationMethod"`
		EncryptionMethod     int    `mapstructure:"encryptionMethod"`
		PSKPassphrase        string `mapstructure:"pskPassphrase"`
		Ieee8021xProfileName string `mapstructure:"ieee8021xProfileName"`
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
		ProfileName            string `mapstructure:"profileName"`
		Username               string `mapstructure:"username"`
		AuthenticationProtocol int    `mapstructure:"authenticationProtocol"`
		ClientCert             string `mapstructure:"clientCert"`
		CaCert                 string `mapstructure:"caCert"`
		PrivateKey             string `mapstructure:"privateKey"`
		Password               string `mapstructure:"password"`
	}

	ACMSetting struct {
		AMTPassword         string `mapstructure:"amtPassword"`
		ProvisioningCert    string `mapstructure:"provisioningCert"`
		ProvisioningCertPwd string `mapstructure:"provisioningCertPwd"`
	}
)
