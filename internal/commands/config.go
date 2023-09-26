package commands

type AppConfig struct {
	AcmActivate struct {
		AmtPassword         string `mapstructure:"amtPassword"`
		ProvisioningCert    string `mapstructure:"provisioningCert"`
		ProvisioningCertPwd string `mapstructure:"provisioningCertPwd"`
	} `mapstructure:"acmActivate"`
	WifiConfigs []struct {
		ProfileName          string `mapstructure:"profileName"`
		SSID                 string `mapstructure:"ssid"`
		Priority             int    `mapstructure:"priority"`
		AuthenticationMethod int    `mapstructure:"authenticationMethod"`
		EncryptionMethod     int    `mapstructure:"encryptionMethod"`
		PSKPassphrase        string `mapstructure:"pskPassphrase"`
		Ieee8021xProfileName string `mapstructure:"ieee8021xProfileName"`
	} `mapstructure:"wifiConfigs"`
	Ieee8021xConfigs []struct {
		ProfileName           string `mapstructure:"profileName"`
		Username              string `mapstructure:"username"`
		AuthenticationProtocol int    `mapstructure:"authenticationProtocol"`
		ClientCert            string `mapstructure:"clientCert"`
		CaCert                string `mapstructure:"caCert"`
		PrivateKey            string `mapstructure:"privateKey"`
		Password              string `mapstructure:"password"`
	} `mapstructure:"ieee8021xConfigs"`
}
