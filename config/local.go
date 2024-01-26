package config

// Config holds the overall configuration.
type Config struct {
	Password         string           `yaml:"password"`
	WifiProfiles      []WifiProfile     `yaml:"wifiProfiles"`
	Ieee8021xProfiles []Ieee8021xProfile `yaml:"ieee8021xProfiles"`
	ACMSettings      ACMSettings      `yaml:"acmSettings"`
}

// WifiConfig holds the configuration for a Wi-Fi network.
type WifiProfile struct {
	ProfileName          string `mapstructure:"profileName"`
	SSID                 string `mapstructure:"ssid"`
	Priority             int    `mapstructure:"priority"`
	AuthenticationMethod int    `mapstructure:"authenticationMethod"`
	EncryptionMethod     int    `mapstructure:"encryptionMethod"`
	PSKPassphrase        string `mapstructure:"pskPassphrase"`
	Ieee8021xProfileName string `mapstructure:"ieee8021xProfileName"`
}

// SecretConfig holds configurations for secrets.
type SecretConfig struct {
	Secrets []Secret `yaml:"secrets"`
}

// Secret holds secret configuration for a profile.
type Secret struct {
	ProfileName   string `yaml:"profileName"`
	PskPassphrase string `yaml:"pskPassphrase"`
	PrivateKey    string `yaml:"privateKey"`
	Password      string `yaml:"password"`
}

// Ieee8021xConfig holds the configuration for an IEEE 802.1X network.
type Ieee8021xProfile struct {
	ProfileName            string `mapstructure:"profileName"`
	Username               string `mapstructure:"username"`
	AuthenticationProtocol int    `mapstructure:"authenticationProtocol"`
	ClientCert             string `mapstructure:"clientCert"`
	CaCert                 string `mapstructure:"caCert"`
	PrivateKey             string `mapstructure:"privateKey"`
	Password               string `mapstructure:"password"`
}

// ACMSettings holds the settings for ACM (Active Configuration Management).
type ACMSettings struct {
	AMTPassword         string `yaml:"amtPassword"`
	ProvisioningCert    string `yaml:"provisioningCert"`
	ProvisioningCertPwd string `yaml:"provisioningCertPwd"`
}

type IPConfiguration struct {
	IPAddress    string `mapstructure:"ipAddress"`
	Netmask      string `mapstructure:"netmask"`
	Gateway      string `mapstructure:"gateway"`
	PrimaryDNS   string `mapstructure:"primaryDNS"`
	SecondaryDNS string `mapstructure:"secondaryDNS"`
}

type AmtInfo struct {
	Ver         bool
	Bld         bool
	Sku         bool
	UUID        bool
	Mode        bool
	DNS         bool
	Cert        bool
	UserCert    bool
	Ras         bool
	Lan         bool
	Hostname    bool
	AMTPassword string
}