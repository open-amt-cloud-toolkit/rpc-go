package flags

import (
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"
	"rpc/internal/config"
	"rpc/pkg/utils"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleConfigureCommand(t *testing.T) {
	cases := []struct {
		description    string
		cmdLine        string
		flagsLocal     bool
		expectedResult int
	}{
		// {description: "Basic wifi config command line",
		// 	cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority 1 -PskPassphrase \"mypassword\" -Ieee8021xProfileName \"\"",
		// 	flagsLocal:     true,
		// 	expectedResult: utils.Success,
		// },
		{description: "Missing Ieee8021xProfileName value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority 1 -PskPassphrase \"mypassword\" -Ieee8021xProfileName",
			flagsLocal:     false,
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing PskPassphrase value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority 1 -PskPassphrase",
			flagsLocal:     false,
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing priority value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority",
			flagsLocal:     false,
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing ssid value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid",
			flagsLocal:     false,
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing authenticationMethod value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod",
			flagsLocal:     false,
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing profile name",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename",
			flagsLocal:     false,
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing filename",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -config",
			flagsLocal:     false,
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Valid with reading from file",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -config ../../config-wifi.yaml",
			flagsLocal:     true,
			expectedResult: utils.Success,
		},
	}
	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			flags := NewFlags(args)
			gotResult := flags.ParseFlags()

			assert.Equal(t, flags.Local, tc.flagsLocal)
			assert.Equal(t, tc.expectedResult, gotResult)
			assert.Equal(t, utils.CommandConfigure, flags.Command)
			assert.Equal(t, utils.SubCommandAddWifiSettings, flags.SubCommand)
		})
	}
}

var wifiCfgWPA = config.WifiConfig{
	ProfileName:          "wifiWPA",
	SSID:                 "ssid",
	Priority:             1,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA_PSK),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
}

var wifiCfgWPA2 = config.WifiConfig{
	ProfileName:          "wifiWPA2",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA2_PSK),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
	PskPassphrase:        "wifiWPAPassPhrase",
}

var wifiCfgWPA8021xEAPTLS = config.WifiConfig{
	ProfileName:          "wifiWPA28021x",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA_IEEE8021x),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
	Ieee8021xProfileName: "ieee8021xCfgEAPTLS",
}

var ieee8021xCfgEAPTLS = config.Ieee8021xConfig{
	ProfileName:            "ieee8021xCfgEAPTLS",
	Username:               "username",
	Password:               "",
	AuthenticationProtocol: int(models.AuthenticationProtocolEAPTLS),
	ClientCert:             "clientCert",
	CACert:                 "caCert",
	PrivateKey:             "privateKey",
}

var wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2 = config.WifiConfig{
	ProfileName:          "wifiWPA28021x",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA2_IEEE8021x),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
	Ieee8021xProfileName: "ieee8021xCfgPEAPv0_EAPMSCHAPv2",
}

var ieee8021xCfgPEAPv0_EAPMSCHAPv2 = config.Ieee8021xConfig{
	ProfileName:            "ieee8021xCfgPEAPv0_EAPMSCHAPv2",
	Username:               "username",
	Password:               "password",
	AuthenticationProtocol: int(models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2),
	ClientCert:             "clientCert",
	CACert:                 "caCert",
	PrivateKey:             "privateKey",
}

func runVerifyWifiConfiguration(t *testing.T, expectedResult int, wifiCfgs config.WifiConfigs, ieee8021xCfgs config.Ieee8021xConfigs) {
	f := Flags{}
	for _, cfg := range wifiCfgs {
		f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, cfg)
	}
	for _, cfg := range ieee8021xCfgs {
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, cfg)
	}
	gotResult := f.verifyWifiConfigurationFile()
	assert.Equal(t, expectedResult, gotResult)
}

func TestVerifyWifiConfigurationFile(t *testing.T) {

	t.Run("expect Success for correct configs", func(t *testing.T) {
		runVerifyWifiConfiguration(t, utils.Success,
			config.WifiConfigs{wifiCfgWPA, wifiCfgWPA2, wifiCfgWPA8021xEAPTLS, wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS, ieee8021xCfgPEAPv0_EAPMSCHAPv2})
	})
	t.Run("expect MissingOrIncorrectProfile when missing ProfileName", func(t *testing.T) {
		orig := wifiCfgWPA.ProfileName
		wifiCfgWPA.ProfileName = ""
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.ProfileName = orig
	})
	t.Run("expect MissingOrIncorrectProfile when missing SSID", func(t *testing.T) {
		orig := wifiCfgWPA.SSID
		wifiCfgWPA.SSID = ""
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.SSID = orig
	})
	t.Run("expect MissingOrIncorrectProfile with invalid Priority", func(t *testing.T) {
		orig := wifiCfgWPA.Priority
		wifiCfgWPA.Priority = 0
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.Priority = orig
	})
	t.Run("expect MissingOrIncorrectProfile with invalid AuthenticationMethod", func(t *testing.T) {
		orig := wifiCfgWPA.AuthenticationMethod
		wifiCfgWPA.AuthenticationMethod = 0
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.AuthenticationMethod = orig
	})
	t.Run("expect MissingOrIncorrectProfile with invalid EncryptionMethod", func(t *testing.T) {
		orig := wifiCfgWPA.EncryptionMethod
		wifiCfgWPA.EncryptionMethod = 0
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.EncryptionMethod = orig
	})
	t.Run("expect MissingOrIncorrectProfile with missing passphrase", func(t *testing.T) {
		orig := wifiCfgWPA2.PskPassphrase
		wifiCfgWPA2.PskPassphrase = ""
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA2},
			config.Ieee8021xConfigs{})
		wifiCfgWPA2.PskPassphrase = orig
	})
	t.Run("expect MissingOrIncorrectProfile with missing ieee8021x ProfileName", func(t *testing.T) {
		orig8021xName := ieee8021xCfgEAPTLS.ProfileName
		ieee8021xCfgEAPTLS.ProfileName = ""
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA8021xEAPTLS},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS})
		ieee8021xCfgEAPTLS.ProfileName = orig8021xName
	})
	t.Run("expect MissingOrIncorrectProfile with PskPassphrase is present for ieee8021x profile", func(t *testing.T) {
		wifiCfgWPA8021xEAPTLS.PskPassphrase = "shouldn't be here"
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA8021xEAPTLS},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS})
		wifiCfgWPA8021xEAPTLS.PskPassphrase = ""
	})
	t.Run("expect MissingOrIncorrectProfile with PskPassphrase is present for ieee8021x profile", func(t *testing.T) {
		wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2.PskPassphrase = "shouldn't be here"
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2},
			config.Ieee8021xConfigs{ieee8021xCfgPEAPv0_EAPMSCHAPv2})
		wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2.PskPassphrase = ""
	})

	t.Run("expect MissingOrIncorrectProfile with duplicate ieee8021x ProfileName", func(t *testing.T) {
		orig8021xName := ieee8021xCfgEAPTLS.ProfileName
		ieee8021xCfgEAPTLS.ProfileName = ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName
		wifiCfgWPA8021xEAPTLS.Ieee8021xProfileName = ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName
		// authMethod 5
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA8021xEAPTLS},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS, ieee8021xCfgPEAPv0_EAPMSCHAPv2})
		// authMethod 7
		runVerifyWifiConfiguration(t, utils.MissingOrIncorrectProfile,
			config.WifiConfigs{wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS, ieee8021xCfgPEAPv0_EAPMSCHAPv2})
		ieee8021xCfgEAPTLS.ProfileName = orig8021xName
		wifiCfgWPA8021xEAPTLS.Ieee8021xProfileName = ieee8021xCfgEAPTLS.ProfileName
	})
}

func TestIeee8021xCfgIsEmpty(t *testing.T) {
	emptyConfig := config.Ieee8021xConfig{}
	notEmptyConfig := config.Ieee8021xConfig{
		ProfileName:            "wifi-8021x",
		Username:               "user",
		Password:               "pass",
		AuthenticationProtocol: 1,
		ClientCert:             "cert",
		CACert:                 "caCert",
		PrivateKey:             "key",
	}

	empty := ieee8021xCfgIsEmpty(emptyConfig)
	if !empty {
		t.Errorf("Expected empty config to return true, but got false")
	}

	notEmpty := ieee8021xCfgIsEmpty(notEmptyConfig)
	if notEmpty {
		t.Errorf("Expected non-empty config to return false, but got true")
	}
}
