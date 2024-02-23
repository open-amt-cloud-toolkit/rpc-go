package local

import (
	"net/url"
	"rpc/internal/config"
	"rpc/internal/flags"
	"testing"
)

var service = ProvisioningService{
	flags:                  &flags.Flags{},
	serverURL:              &url.URL{},
	interfacedWsmanMessage: nil,
	config:                 &config.Config{},
	amtCommand:             nil,
	handlesWithCerts:       map[string]string{},
	networker:              nil,
}

func TestAddWiredSettings(t *testing.T) {
	happyService := service
	happyService.flags.
}

// func TestAddWifiSettings(t *testing.T) {
// 	f := &flags.Flags{}
// 	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)

// 	t.Run("expect success when AddWifiSettings", func(t *testing.T) {
// 		lps := setupService(f)
// 		err := lps.AddWifiSettings()
// 		assert.NoError(t, err)
// 	})
// 	t.Run("expect error failed wifi port", func(t *testing.T) {
// 		errEnableWiFi = errTestError
// 		lps := setupService(f)
// 		err := lps.AddWifiSettings()
// 		assert.Error(t, err)
// 		errEnableWiFi = nil
// 	})
// }

// func TestProcessWifiConfigs(t *testing.T) {
// 	f := &flags.Flags{}
// 	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)

// 	t.Run("expect success processing wifi configs", func(t *testing.T) {
// 		lps := setupService(f)
// 		err := lps.ProcessWifiConfigs()
// 		assert.NoError(t, err)
// 	})
// 	t.Run("expect warning processing 2 wifi configs with 1 bad-name", func(t *testing.T) {
// 		f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA2)
// 		f.LocalConfig.WifiConfigs[1].ProfileName = "bad-name"
// 		lps := setupService(f)
// 		err := lps.ProcessWifiConfigs()
// 		assert.Equal(t, utils.WifiConfigurationWithWarnings, err)
// 	})
// }

// func TestProcessWifiConfig(t *testing.T) {
// 	f := &flags.Flags{}

// 	// bad name error already tested
// 	t.Run("expect success when handling ieee8021x config", func(t *testing.T) {
// 		orig := wifiCfgWPA8021xEAPTLS.AuthenticationMethod
// 		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = int(wifi.AuthenticationMethod_WPA_IEEE8021x)
// 		f.LocalConfig.Ieee8021xConfigs = []config.Ieee8021xConfig{
// 			ieee8021xCfgEAPTLS,
// 		}
// 		lps := setupService(f)
// 		err := lps.ProcessWifiConfig(&wifiCfgWPA8021xEAPTLS)
// 		assert.NoError(t, err)
// 		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = orig
// 	})
// 	t.Run("expect success when handling non-ieee8021x config", func(t *testing.T) {
// 		lps := setupService(f)
// 		err := lps.ProcessWifiConfig(&wifiCfgWPA2)
// 		assert.NoError(t, err)
// 	})

// }
// func TestPruneWifiConfigs(t *testing.T) {
// 	f := &flags.Flags{}

// 	t.Run("expect Success when there are no configs", func(t *testing.T) {
// 		lps := setupService(f)
// 		tempStorage := getWiFiSettingsResponse
// 		// empty the response
// 		getWiFiSettingsResponse = []wifi.WiFiEndpointSettingsResponse{}
// 		err := lps.PruneWifiConfigs()
// 		assert.NoError(t, err)
// 		//restore
// 		getWiFiSettingsResponse = tempStorage
// 	})
// 	t.Run("expect success when there are configs", func(t *testing.T) {
// 		lps := setupService(f)
// 		err := lps.PruneWifiConfigs()
// 		assert.NoError(t, err)
// 	})
// }

// func TestEnableWifiErrors(t *testing.T) {
// 	f := &flags.Flags{}
// 	t.Run("expect success for EnableWifi", func(t *testing.T) {
// 		lps := setupService(f)
// 		err := lps.EnableWifiPort()
// 		assert.NoError(t, err)
// 	})
// 	t.Run("expect failure for EnableWifi", func(t *testing.T) {
// 		errEnableWiFi = errTestError
// 		lps := setupService(f)
// 		err := lps.EnableWifiPort()
// 		assert.Error(t, err)
// 		errEnableWiFi = nil
// 	})

// }
// func TestGetWifiIeee8021xCerts(t *testing.T) {
// 	f := &flags.Flags{}
// 	t.Run("expect all error paths traversed for coverage", func(t *testing.T) {
// 		lps := setupService(f)
// 		certHandles, keyPairHandles, err := lps.GetWifiIeee8021xCerts()
// 		assert.NoError(t, err)
// 		assert.Equal(t, 2, len(certHandles))
// 		assert.Equal(t, 1, len(keyPairHandles))
// 		assert.Equal(t, caCert.X509Certificate, lps.handlesWithCerts["Intel(r) AMT Certificate: Handle: 1"])
// 	})
// }
// func TestRollbackAddedItems(t *testing.T) {
// 	f := &flags.Flags{}
// 	handles := Handles{
// 		privateKeyHandle: "privateKeyHandle",
// 		clientCertHandle: "clientCertHandle",
// 		rootCertHandle:   "rootCertHandle",
// 	}

// 	t.Run("expect all error paths traversed for coverage", func(t *testing.T) {
// 		lps := setupService(f)
// 		lps.RollbackAddedItems(&handles)
// 	})
// 	t.Run("expect all happy paths traversed for coverage", func(t *testing.T) {
// 		lps := setupService(f)
// 		lps.RollbackAddedItems(&handles)
// 	})
// }
