package local

import (
	"errors"
	"rpc/internal/config"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"

	"github.com/stretchr/testify/assert"
)

type testCase struct {
	name           string
	controlMode    int
	controlModeErr error
	setupMEBXResp  int
	setupMEBXErr   error
	expectedErr    error
}

func TestSetMebx(t *testing.T) {
	tests := []testCase{
		{
			name:           "GetControlModeError",
			controlModeErr: assert.AnError,
			expectedErr:    utils.AMTConnectionFailed,
		},
		{
			name:        "NotACM",
			controlMode: 1, // Not ACM
			expectedErr: utils.SetMEBXPasswordFailed,
		},
		{
			name:         "SetupMEBXError",
			controlMode:  2,
			setupMEBXErr: assert.AnError,
			expectedErr:  assert.AnError,
		},
		{
			name:          "SetupMEBXFailReturnValue",
			controlMode:   2,
			setupMEBXResp: 1,
			expectedErr:   utils.SetMEBXPasswordFailed,
		},
		{
			name:          "Success",
			controlMode:   2,
			setupMEBXResp: 0,
			expectedErr:   nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f) // Placeholder for actual service initialization
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman

			mockControlMode = tc.controlMode
			mockControlModeErr = tc.controlModeErr

			mockSetupAndConfigurationValue = tc.setupMEBXResp
			mockSetupAndConfigurationErr = tc.setupMEBXErr

			err := service.SetMebx()

			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

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
var errTestError = errors.New("test error")

func TestConfigure(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect error for unhandled Subcommand", func(t *testing.T) {
		lps := setupService(&flags.Flags{})
		err := lps.Configure()
		assert.Equal(t, utils.IncorrectCommandLineParameters, err)
	})
	t.Run("expect error for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandAddWifiSettings
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.Configure()
		assert.Error(t, err)
		errEnableWiFi = nil
	})
	t.Run("expect success for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandAddWifiSettings
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
	})
	t.Run("expect error for SubCommandEnableWifiPort", func(t *testing.T) {
		f.SubCommand = utils.SubCommandEnableWifiPort
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.Configure()
		assert.Error(t, err)
		errEnableWiFi = nil
	})
	t.Run("expect success for SubCommandEnableWifiPort", func(t *testing.T) {
		f.SubCommand = utils.SubCommandEnableWifiPort
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
	})
	t.Run("expect error for SetMebx", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSetMEBx
		lps := setupService(f)
        mockSetupAndConfigurationErr = errTestError
		err := lps.Configure()
		assert.Error(t, err)
		mockSetupAndConfigurationErr = nil
	})
	t.Run("expect success for SetMebx", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSetMEBx
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
	})
}

func TestAddWifiSettings(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)

	t.Run("expect success when AddWifiSettings", func(t *testing.T) {
		lps := setupService(f)
		err := lps.AddWifiSettings()
		assert.NoError(t, err)
	})
	t.Run("expect error failed wifi port", func(t *testing.T) {
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.AddWifiSettings()
		assert.Error(t, err)
		errEnableWiFi = nil
	})
}

func TestProcessWifiConfigs(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)

	t.Run("expect success processing wifi configs", func(t *testing.T) {
		lps := setupService(f)
		err := lps.ProcessWifiConfigs()
		assert.NoError(t, err)
	})
	t.Run("expect warning processing 2 wifi configs with 1 bad-name", func(t *testing.T) {
		f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA2)
		f.LocalConfig.WifiConfigs[1].ProfileName = "bad-name"
		lps := setupService(f)
		err := lps.ProcessWifiConfigs()
		assert.Equal(t, utils.WifiConfigurationWithWarnings, err)
	})
}

func TestProcessWifiConfig(t *testing.T) {
	f := &flags.Flags{}

	// bad name error already tested
	t.Run("expect success when handling ieee8021x config", func(t *testing.T) {
		orig := wifiCfgWPA8021xEAPTLS.AuthenticationMethod
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = int(wifi.AuthenticationMethod_WPA_IEEE8021x)
		f.LocalConfig.Ieee8021xConfigs = []config.Ieee8021xConfig{
			ieee8021xCfgEAPTLS,
		}
		lps := setupService(f)
		err := lps.ProcessWifiConfig(&wifiCfgWPA8021xEAPTLS)
		assert.NoError(t, err)
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = orig
	})
	t.Run("expect success when handling non-ieee8021x config", func(t *testing.T) {
		lps := setupService(f)
		err := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.NoError(t, err)
	})

}
func TestPruneWifiConfigs(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect Success when there are no configs", func(t *testing.T) {
		lps := setupService(f)
		tempStorage := getWiFiSettingsResponse
		// empty the response
		getWiFiSettingsResponse = []wifi.WiFiEndpointSettingsResponse{}
		err := lps.PruneWifiConfigs()
		assert.NoError(t, err)
		//restore
		getWiFiSettingsResponse = tempStorage
	})
	t.Run("expect success when there are configs", func(t *testing.T) {
		lps := setupService(f)
		err := lps.PruneWifiConfigs()
		assert.NoError(t, err)
	})
}

func TestEnableWifiErrors(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect success for EnableWifi", func(t *testing.T) {
		lps := setupService(f)
		err := lps.EnableWifiPort()
		assert.NoError(t, err)
	})
	t.Run("expect failure for EnableWifi", func(t *testing.T) {
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.EnableWifiPort()
		assert.Error(t, err)
		errEnableWiFi = nil
	})

}
func TestGetWifiIeee8021xCerts(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect all error paths traversed for coverage", func(t *testing.T) {
		lps := setupService(f)
		certHandles, keyPairHandles, err := lps.GetWifiIeee8021xCerts()
		assert.NoError(t, err)
		assert.Equal(t, 2, len(certHandles))
		assert.Equal(t, 1, len(keyPairHandles))
		assert.Equal(t, caCert.X509Certificate, lps.handlesWithCerts["Intel(r) AMT Certificate: Handle: 1"])
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
