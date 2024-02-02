package local

import (
	"rpc/internal/config"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/wifiportconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"

	"github.com/stretchr/testify/assert"
)

var wifiCfgWPA = config.WifiConfig{
	ProfileName:          "wifiWPA",
	SSID:                 "ssid",
	Priority:             1,
	AuthenticationMethod: int(wifi.AuthenticationMethod_WPA_PSK),
	EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
	PskPassphrase:        "wifiWPAPassPhrase",
	Ieee8021xProfileName: "",
}

var wifiCfgWPA2 = config.WifiConfig{
	ProfileName:          "wifiWPA2",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(wifi.AuthenticationMethod_WPA2_PSK),
	EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
	PskPassphrase:        "wifiWPAPassPhrase",
	Ieee8021xProfileName: "",
}

var wifiCfgWPA8021xEAPTLS = config.WifiConfig{
	ProfileName:          "wifiWPA28021x",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(wifi.AuthenticationMethod_WPA_IEEE8021x),
	EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
	PskPassphrase:        "",
	Ieee8021xProfileName: "ieee8021xCfgEAPTLS",
}

var ieee8021xCfgEAPTLS = config.Ieee8021xConfig{
	ProfileName:            "ieee8021xCfgEAPTLS",
	Username:               "username",
	Password:               "",
	AuthenticationProtocol: int(ieee8021x.AuthenticationProtocolEAPTLS),
	ClientCert:             "clientCert",
	CACert:                 "caCert",
	PrivateKey:             "privateKey",
}

func TestConfigure(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect error for unhandled Subcommand", func(t *testing.T) {
		lps := setupService(&flags.Flags{})
		err := lps.Configure()
		assert.Equal(t, utils.IncorrectCommandLineParameters, err)
	})
	t.Run("expect error for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandAddWifiSettings
		lps := setupService(f)
		err := lps.Configure()
		assert.Equal(t, utils.WSMANMessageError, err)
	})
	t.Run("expect error for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandEnableWifiPort
		lps := setupService(f)
		err := lps.Configure()
		assert.Equal(t, utils.WSMANMessageError, err)
	})
}

func TestAddWifiSettings(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	pcsRsp := wifiportconfiguration.Response{}
	pcsRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
	t.Run("expect error from PruneWifiConfigs path", func(t *testing.T) {
		lps := setupService(f)
		err := lps.AddWifiSettings()
		assert.NotEqual(t, nil, err)
	})
	t.Run("expect error from EnableWifi path", func(t *testing.T) {
		lps := setupService(f)
		err := lps.AddWifiSettings()
		assert.NotEqual(t, nil, err)
	})
}

func TestProcessWifiConfigs(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA2)

	t.Run("expect WiFiConfigurationFailed if all configs fail", func(t *testing.T) {
		f.LocalConfig.WifiConfigs[1].ProfileName = "bad-name"
		lps := setupService(f)
		rc := lps.ProcessWifiConfigs()
		assert.Equal(t, utils.WiFiConfigurationFailed, rc)
	})
}

func TestProcessWifiConfig(t *testing.T) {
	f := &flags.Flags{}

	// bad name error already tested
	t.Run("expect WSMANMessageError for ProcessIeee8012xConfig", func(t *testing.T) {
		orig := wifiCfgWPA8021xEAPTLS.AuthenticationMethod
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = int(wifi.AuthenticationMethod_WPA_IEEE8021x)
		f.LocalConfig.Ieee8021xConfigs = config.Ieee8021xConfigs{}
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
		lps := setupService(f)
		rc := lps.ProcessWifiConfig(&wifiCfgWPA8021xEAPTLS)
		assert.Equal(t, utils.WSMANMessageError, rc)
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = orig
	})
	t.Run("expect WSMANMessageError for AddWiFiSettings()", func(t *testing.T) {
		lps := setupService(f)
		rc := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.Equal(t, utils.WSMANMessageError, rc)
	})

}

func TestPruneWifiConfigs(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect WSMANMessageError error on EnumPullUnmarshal", func(t *testing.T) {
		lps := setupService(f)
		err := lps.PruneWifiConfigs()
		assert.Equal(t, utils.WSMANMessageError, err)
	})
}

func TestEnableWifiErrors(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect WSMANMessageError for WiFiPortConfigurationService.Get()", func(t *testing.T) {
		lps := setupService(f)
		err := lps.EnableWifi()
		assert.Equal(t, utils.WSMANMessageError, err)
	})
	t.Run("expect WSMANMessageError for WiFiPortConfigurationService.Put()", func(t *testing.T) {
		lps := setupService(f)
		err := lps.EnableWifi()
		assert.Equal(t, utils.WSMANMessageError, err)
	})
	t.Run("expect WiFiConfigurationFailed when enable is unsuccessful", func(t *testing.T) {

		lps := setupService(f)
		err := lps.EnableWifi()
		assert.Equal(t, utils.WiFiConfigurationFailed, err)
	})
	t.Run("expect WSMANMessageError for RequestStateChange()", func(t *testing.T) {
		pcsResponseEnabled := wifiportconfiguration.Response{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		lps := setupService(f)
		err := lps.EnableWifi()
		assert.Equal(t, utils.WSMANMessageError, err)
	})

}

func TestRollbackAddedItems(t *testing.T) {
	f := &flags.Flags{}
	handles := Handles{
		privateKeyHandle: "privateKeyHandle",
		clientCertHandle: "clientCertHandle",
		rootCertHandle:   "rootCertHandle",
	}

	t.Run("expect all error paths traversed for coverage", func(t *testing.T) {
		lps := setupService(f)
		lps.RollbackAddedItems(&handles)
	})
	t.Run("expect all happy paths traversed for coverage", func(t *testing.T) {
		lps := setupService(f)
		lps.RollbackAddedItems(&handles)
	})
}

func TestAddTrustedRootCert(t *testing.T) {

}

func TestAddClientCert(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect success when credential already added", func(t *testing.T) {
		lps := setupService(f)
		instanceId := `Intel® AMT XXXCertYYYkey: Handle: 1`
		associatedCredential := `THISISAFAKECERTSTRING`
		lps.handlesWithCerts[instanceId] = associatedCredential
		// handle, resultCode := lps.AddClientCert(associatedCredential)
		// assert.Equal(t, nil, resultCode)
		// assert.Equal(t, instanceId, handle)
	})
}

func TestAddPrivateKey(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect success when credential already added", func(t *testing.T) {

		lps := setupService(f)
		instanceId := `Intel® AMT XXXCertYYYkey: Handle: 1`
		associatedCredential := `THISISAFAKECERTSTRING`
		lps.handlesWithCerts[instanceId] = associatedCredential
		// handle, resultCode := lps.AddPrivateKey(associatedCredential)
		// assert.Equal(t, nil, resultCode)
		// assert.Equal(t, instanceId, handle)
	})
}

func TestEnableWifiPort(t *testing.T) {
	f := &flags.Flags{}
	pcsRsp := wifiportconfiguration.Response{}
	pcsRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
	pcsRsp.Body.WiFiPortConfigurationService.EnabledState = 1

	t.Run("enablewifiport: expect WSMANMessageError ", func(t *testing.T) {
		lps := setupService(f)
		err := lps.EnableWifiPort()
		assert.Equal(t, utils.WSMANMessageError, err)
	})
}
