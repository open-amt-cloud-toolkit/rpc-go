package config

// Config holds the overall configuration.
type Config struct {
	IsLocal             bool                `mapstructure:"isLocal"`
	Command             string              `mapstructure:"command"`
	LMSConfig           LMSConfig           `mapstructure:"lmsConfig"`
	Password            string              `mapstructure:"password"`
	WifiProfiles        []WifiProfile       `mapstructure:"wifiProfiles"`
	Ieee8021xProfiles   []Ieee8021xProfile  `mapstructure:"ieee8021xProfiles"`
	ACMSettings         ACMSettings         `mapstructure:"acmSettings"`
	ActivationProfile   ActivationProfile   `mapstructure:"activationProfile"`
	DeactivationProfile DeactivationProfile `mapstructure:"deactivationProfile"`
}

type LMSConfig struct {
	LMSAddress string `mapstructure:"LMSAddress"`
	LMSPort    string `mapstructure:"LMSPort"`
}

type DeactivationProfile struct {
	URL         string `mapstructure:"URL"`
	AMTPassword string `mapstructure:"AMTPassword"`
}

type ActivationProfile struct {
	URL                 string `mapstructure:"URL"`
	Profile             string `mapstructure:"Profile"`
	UUID                string `mapstructure:"UUID"`
	Name                string `mapstructure:"Name"`
	DNS                 string `mapstructure:"DNS"`
	Hostname            string `mapstructure:"Hostname"`
	CCMMode             bool   `mapstructure:"CCMMode"`
	ACMMode             bool   `mapstructure:"ACMMode"`
	ConfigPathOrString  string `mapstructure:"ConfigPathOrString"`
	ConfigJSONString    string `mapstructure:"ConfigJSONString"`
	ConfigYAMLString    string `mapstructure:"ConfigYAMLString"`
	AMTPassword         string `mapstructure:"AMTPassword"`
	ProvisioningCert    string `mapstructure:"ProvisioningCert"`
	ProvisioningCertPwd string `mapstructure:"ProvisioningCertPwd"`
	NoCertverification  bool   `mapstructure:"NoCertverification"`
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
