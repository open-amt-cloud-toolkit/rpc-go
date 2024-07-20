package config

// Config holds the overall configuration.
type Config struct {
	IsLocal    bool       `mapstructure:"isLocal"`
	Command    string     `mapstructure:"command"`
	LMSConfig  LMSConfig  `mapstructure:"lmsConfig"`
	Activate   Activate   `mapstructure:"activation"`
	Deactivate Deactivate `mapstructure:"deactivation"`
	Configure  Configure  `mapstructure:"configure"`
	Provision  Provision  `mapstructure:"provision"`
}

type Provision struct {
	Activation    Activate  `mapstructure:"activation"`
	Configuration Configure `mapstructure:"amtConfiguration"`
}

type Configure struct {
	Subcommand         string              `mapstructure:"subcommand"`
	ConfigPathOrString string              `mapstructure:"config"`
	ConfigJSONString   string              `mapstructure:"configjson"`
	ConfigYAMLString   string              `mapstructure:"configyaml"`
	AMTPassword        string              `mapstructure:"amtPassword"`
	NewAMTPassword     string              `mapstructure:"newAMTPassword"`
	MEBxPassword       string              `mapstructure:"mebxPassword"`
	AMTFeatures        AMTFeatures         `mapstructure:"amtFeatures"`
	TLS                TLS                 `mapstructure:"tls"`
	EA                 EnterpriseAssistant `mapstructure:"enterpriseAssistant"`
	WifiProfiles       []WifiProfile       `mapstructure:"wifiProfiles"`
	Ieee8021xProfiles  []Ieee8021xProfile  `mapstructure:"ieee8021xProfiles"`
}

type LMSConfig struct {
	LMSAddress string `mapstructure:"LMSAddress"`
	LMSPort    string `mapstructure:"LMSPort"`
}

type Deactivate struct {
	URL         string `mapstructure:"url"`
	AMTPassword string `mapstructure:"amtPassword"`
}

type Activate struct {
	URL                 string `mapstructure:"url"`
	Profile             string `mapstructure:"profile"`
	UUID                string `mapstructure:"uuid"`
	Name                string `mapstructure:"name"`
	DNS                 string `mapstructure:"dns"`
	Hostname            string `mapstructure:"hostname"`
	Mode                string `mapstructure:"mode"`
	ConfigPathOrString  string `mapstructure:"config"`
	ConfigJSONString    string `mapstructure:"configJSON"`
	ConfigYAMLString    string `mapstructure:"configYAML"`
	AMTPassword         string `mapstructure:"amtPassword"`
	ProvisioningCert    string `mapstructure:"provisioningCert"`
	ProvisioningCertPwd string `mapstructure:"provisioningCertPwd"`
	NoCertverification  bool   `mapstructure:"noCertverification"`
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

type AMTFeatures struct {
	KVM         bool
	SOL         bool
	IDER        bool
	UserConsent string
}

type EnterpriseAssistant struct {
	Address    string `mapstructure:"eaAddress"`
	Username   string `mapstructure:"eaUsername"`
	Password   string `mapstructure:"eaPassword"`
	Configured bool   `mapstructure:"eaConfigured"`
}

type TLS struct {
	Delay int    `mapstructure:"delay" env-default:"3"`
	Mode  string `mapstructure:"mode"`
}

type Ethernet struct {
	DHCP                 bool   `yaml:"dhcp"`
	Static               bool   `yaml:"static"`
	IpSync               bool   `yaml:"ipsync"`
	IpAddress            string `yaml:"ipaddress"`
	Subnetmask           string `yaml:"subnetmask"`
	Gateway              string `yaml:"gateway"`
	PrimaryDNS           string `yaml:"primarydns"`
	SecondaryDNS         string `yaml:"secondarydns"`
	Ieee8021xProfileName string `yaml:"ieee8021xProfileName"`
}
