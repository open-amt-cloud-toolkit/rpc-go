package flags

import (
	"fmt"
	"rpc/internal/config"
	"rpc/pkg/utils"
	"strings"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"

	"github.com/stretchr/testify/assert"
)

func getPromptForSecretsFlags() Flags {
	f := Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA2)
	f.LocalConfig.WifiConfigs[0].PskPassphrase = ""
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
	f.LocalConfig.Ieee8021xConfigs[0].PrivateKey = ""
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgPEAPv0_EAPMSCHAPv2)
	f.LocalConfig.Ieee8021xConfigs[1].Password = ""
	return f
}

func TestPromptForSecrets(t *testing.T) {

	t.Run("expect success on valid user input", func(t *testing.T) {
		defer userInput(t, "userInput\nuserInput\nuserInput")()
		f := getPromptForSecretsFlags()
		rc := f.promptForSecrets()
		assert.Equal(t, utils.Success, rc)
		assert.Equal(t, "userInput", f.LocalConfig.WifiConfigs[0].PskPassphrase)
		assert.Equal(t, "userInput", f.LocalConfig.Ieee8021xConfigs[0].PrivateKey)
		assert.Equal(t, "userInput", f.LocalConfig.Ieee8021xConfigs[1].Password)
	})
	t.Run("expect InvalidUserInput", func(t *testing.T) {
		defer userInput(t, "userInput\nuserInput")()
		f := getPromptForSecretsFlags()
		rc := f.promptForSecrets()
		assert.Equal(t, utils.InvalidUserInput, rc)
		assert.Equal(t, "userInput", f.LocalConfig.WifiConfigs[0].PskPassphrase)
		assert.Equal(t, "userInput", f.LocalConfig.Ieee8021xConfigs[0].PrivateKey)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[1].Password)
	})
	t.Run("expect InvalidUserInput", func(t *testing.T) {
		defer userInput(t, "userInput")()
		f := getPromptForSecretsFlags()
		rc := f.promptForSecrets()
		assert.Equal(t, utils.InvalidUserInput, rc)
		assert.Equal(t, "userInput", f.LocalConfig.WifiConfigs[0].PskPassphrase)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[0].Password)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[0].PrivateKey)
	})
	t.Run("expect InvalidUserInput", func(t *testing.T) {
		f := getPromptForSecretsFlags()
		rc := f.promptForSecrets()
		assert.Equal(t, utils.InvalidUserInput, rc)
		assert.Equal(t, "", f.LocalConfig.WifiConfigs[0].PskPassphrase)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[0].Password)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[0].PrivateKey)
	})
}

func TestCmdLine(t *testing.T) {
	jsonCfgStr := `{"WifiConfigs":[{"ProfileName":"wifiWPA", "SSID":"ssid", "PskPassphrase": "testPSK", "Priority":1, "AuthenticationMethod":4, "EncryptionMethod":4}]}`

	t.Run("expect IncorrectCommandLineParameters with no subcommand", func(t *testing.T) {
		f := NewFlags([]string{`rpc`, `configure`})
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
	t.Run("expect IncorrectCommandLineParameters with unknown subcommand", func(t *testing.T) {
		f := NewFlags([]string{`rpc`, `configure`, `what-the-heck?`})
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
	t.Run("expect Success", func(t *testing.T) {
		cmdLine := []string{
			`rpc`, `configure`, `addwifisettings`,
			`-password`, `cliP@ss0rd!`,
			`-configJson`, jsonCfgStr,
		}
		f := NewFlags(cmdLine)
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.Success, gotResult)
		assert.Equal(t, true, f.Local)
		assert.Equal(t, f.Password, f.LocalConfig.Password)
	})
	t.Run("expect MissingOrIncorrectPassword", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `addwifisettings`,
			`-configJson`, jsonCfgStr,
		})
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.MissingOrIncorrectPassword, gotResult)
	})
	t.Run("expect Success on password prompt", func(t *testing.T) {
		defer userInput(t, "userP@ssw0rd!")()
		f := NewFlags([]string{
			`rpc`, `configure`, `addwifisettings`,
			`-configJson`, jsonCfgStr,
		})
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.Success, gotResult)
	})
	t.Run("expect Success when password is in config file", func(t *testing.T) {
		defer userInput(t, "userP@ssw0rd!")()
		f := NewFlags([]string{
			`rpc`, `configure`, `addwifisettings`,
			`-configJson`, jsonCfgStr,
		})
		f.LocalConfig.Password = "localP@ssw0rd!"
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.Success, gotResult)
	})
	t.Run("expect MissingOrIncorrectPassword when passwords do not match", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `addwifisettings`,
			`-password`, `cliP@ss0rd!`,
			`-configJson`, jsonCfgStr,
		})
		f.LocalConfig.Password = "localP@ssw0rd!"
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.MissingOrIncorrectPassword, gotResult)
	})
	t.Run("enablewifiport: expect Success", func(t *testing.T) {
		cmdLine := []string{
			`rpc`, `configure`, `enablewifiport`,
			`-password`, `cliP@ss0rd!`,
		}
		f := NewFlags(cmdLine)
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.Success, gotResult)
		assert.Equal(t, true, f.Local)
		assert.Equal(t, f.Password, f.LocalConfig.Password)
	})
	t.Run("enablewifiport: expect MissingOrIncorrectPassword", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `enablewifiport`, `-password`,
		})
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
	t.Run("enablewifiport: expect Success on password prompt", func(t *testing.T) {
		defer userInput(t, "userP@ssw0rd!")()
		f := NewFlags([]string{
			`rpc`, `configure`, `enablewifiport`,
		})
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.Success, gotResult)
	})
	t.Run("enablewifiport: expect IncorrectCommandLineParameters", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `enablewifiport`, `-password`, `testpw`, `toomany`,
		})
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
	t.Run("enablewifiport: ssexpect IncorrectCommandLineParameters", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `enablewifiport`, `-bogus`, `testpw`,
		})
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
}

func TestConfigJson(t *testing.T) {
	cmdLine := `rpc configure addwifisettings -secrets ../../secrets.yaml -password test -configJson {"Password":"","FilePath":"../../config.yaml","WifiConfigs":[{"ProfileName":"wifiWPA2","SSID":"ssid","Priority":1,"AuthenticationMethod":6,"EncryptionMethod":4,"PskPassphrase":"","Ieee8021xProfileName":""},{"ProfileName":"wifi8021x","SSID":"ssid","Priority":2,"AuthenticationMethod":7,"EncryptionMethod":4,"PskPassphrase":"","Ieee8021xProfileName":"ieee8021xEAP-TLS"}],"Ieee8021xConfigs":[{"ProfileName":"ieee8021xEAP-TLS","Username":"test","Password":"","AuthenticationProtocol":0,"ClientCert":"test","CACert":"test","PrivateKey":""},{"ProfileName":"ieee8021xPEAPv0","Username":"test","Password":"","AuthenticationProtocol":2,"ClientCert":"testClientCert","CACert":"testCaCert","PrivateKey":"testPrivateKey"}],"AMTPassword":"","ProvisioningCert":"","ProvisioningCertPwd":""}`
	defer userInput(t, "userInput\nuserInput\nuserInput")()
	args := strings.Fields(cmdLine)
	flags := NewFlags(args)
	gotResult := flags.ParseFlags()
	assert.Equal(t, utils.Success, gotResult)
}

func TestHandleAddWifiSettings(t *testing.T) {
	cases := []struct {
		description    string
		cmdLine        string
		expectedResult utils.ReturnCode
	}{
		{description: "Missing Ieee8021xProfileName value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority 1 -PskPassphrase \"mypassword\" -Ieee8021xProfileName",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing PskPassphrase value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority 1 -PskPassphrase",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing priority value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing ssid value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing authenticationMethod value",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename cliprofname -authenticationMethod",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing profile name",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -profilename",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing filename",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -config",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing password",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -config",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing all params",
			cmdLine:        "rpc configure addwifisettings",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Unknown param",
			cmdLine:        "rpc configure addwifisettings -h",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Basic wifi config command line",
			cmdLine:        `rpc configure addwifisettings -password Passw0rd! -profileName cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid "myclissid" -priority 1 -pskPassphrase "mypassword"`,
			expectedResult: utils.Success,
		},
		{description: "Valid with reading from file",
			cmdLine:        "rpc configure addwifisettings -password Passw0rd! -config ../../config.yaml -secrets ../../secrets.yaml",
			expectedResult: utils.Success,
		},
	}
	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			flags := NewFlags(args)
			gotResult := flags.handleAddWifiSettings()
			assert.Equal(t, tc.expectedResult, gotResult)
		})
	}
}

var wifiCfgWPA = config.WifiConfig{
	ProfileName:          "wifiWPA",
	SSID:                 "ssid",
	Priority:             1,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA_PSK),
	EncryptionMethod:     int(models.EncryptionMethod_TKIP),
	PskPassphrase:        "wifiWPAPassPhrase",
}

var wifiCfgWPA2 = config.WifiConfig{
	ProfileName:          "wifiWPA2",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA2_PSK),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
	PskPassphrase:        "wifiWPA2PassPhrase",
}

var wifiCfgWPA8021xEAPTLS = config.WifiConfig{
	ProfileName:          "wifiWPA28021x",
	SSID:                 "ssid",
	Priority:             3,
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
	Priority:             4,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA2_IEEE8021x),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
	Ieee8021xProfileName: "ieee8021xCfgPEAPv0_EAPMSCHAPv2",
}

var ieee8021xCfgPEAPv0_EAPMSCHAPv2 = config.Ieee8021xConfig{
	ProfileName:            "ieee8021xCfgPEAPv0_EAPMSCHAPv2",
	Username:               "username",
	Password:               "password",
	AuthenticationProtocol: int(models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2),
	ClientCert:             "",
	CACert:                 "caCert",
	PrivateKey:             "",
}

func runVerifyWifiConfiguration(t *testing.T, expectedResult utils.ReturnCode, wifiCfgs config.WifiConfigs, ieee8021xCfgs config.Ieee8021xConfigs) {
	f := Flags{}
	for _, cfg := range wifiCfgs {
		f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, cfg)
	}
	for _, cfg := range ieee8021xCfgs {
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, cfg)
	}
	gotResult := f.verifyWifiConfigurations()
	assert.Equal(t, expectedResult, gotResult)
}

func TestVerifyWifiConfiguration(t *testing.T) {

	t.Run("expect Success for correct configs", func(t *testing.T) {
		runVerifyWifiConfiguration(t, utils.Success,
			config.WifiConfigs{wifiCfgWPA, wifiCfgWPA2, wifiCfgWPA8021xEAPTLS, wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS, ieee8021xCfgPEAPv0_EAPMSCHAPv2})
	})
	t.Run("expect MissingOrInvalidConfiguration when missing ProfileName", func(t *testing.T) {
		orig := wifiCfgWPA.ProfileName
		wifiCfgWPA.ProfileName = ""
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.ProfileName = orig
	})
	t.Run("expect MissingOrInvalidConfiguration when missing SSID", func(t *testing.T) {
		orig := wifiCfgWPA.SSID
		wifiCfgWPA.SSID = ""
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.SSID = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with invalid Priority", func(t *testing.T) {
		orig := wifiCfgWPA.Priority
		wifiCfgWPA.Priority = 0
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.Priority = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with duplicate Priority", func(t *testing.T) {
		orig := wifiCfgWPA.Priority
		wifiCfgWPA.Priority = wifiCfgWPA2.Priority
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA, wifiCfgWPA2},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.Priority = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with invalid AuthenticationMethod", func(t *testing.T) {
		orig := wifiCfgWPA.AuthenticationMethod
		wifiCfgWPA.AuthenticationMethod = int(models.AuthenticationMethod_DMTFReserved)
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.AuthenticationMethod = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with invalid EncryptionMethod", func(t *testing.T) {
		orig := wifiCfgWPA.EncryptionMethod
		wifiCfgWPA.EncryptionMethod = int(models.EncryptionMethod_DMTFReserved)
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA},
			config.Ieee8021xConfigs{})
		wifiCfgWPA.EncryptionMethod = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with missing passphrase", func(t *testing.T) {
		orig := wifiCfgWPA2.PskPassphrase
		wifiCfgWPA2.PskPassphrase = ""
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA2},
			config.Ieee8021xConfigs{})
		wifiCfgWPA2.PskPassphrase = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with missing ieee8021x ProfileName", func(t *testing.T) {
		orig8021xName := ieee8021xCfgEAPTLS.ProfileName
		ieee8021xCfgEAPTLS.ProfileName = ""
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA8021xEAPTLS},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS})
		ieee8021xCfgEAPTLS.ProfileName = orig8021xName
	})
	t.Run("expect MissingOrInvalidConfiguration with PskPassphrase is present for ieee8021x profile", func(t *testing.T) {
		wifiCfgWPA8021xEAPTLS.PskPassphrase = "shouldn't be here"
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA8021xEAPTLS},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS})
		wifiCfgWPA8021xEAPTLS.PskPassphrase = ""
	})
	t.Run("expect MissingOrInvalidConfiguration with PskPassphrase is present for ieee8021x profile", func(t *testing.T) {
		wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2.PskPassphrase = "shouldn't be here"
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2},
			config.Ieee8021xConfigs{ieee8021xCfgPEAPv0_EAPMSCHAPv2})
		wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2.PskPassphrase = ""
	})

	t.Run("expect MissingOrInvalidConfiguration with duplicate ieee8021x ProfileName", func(t *testing.T) {
		orig8021xName := ieee8021xCfgEAPTLS.ProfileName
		ieee8021xCfgEAPTLS.ProfileName = ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName
		wifiCfgWPA8021xEAPTLS.Ieee8021xProfileName = ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName
		// authMethod 5
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA8021xEAPTLS},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS, ieee8021xCfgPEAPv0_EAPMSCHAPv2})
		// authMethod 7
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			config.WifiConfigs{wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2},
			config.Ieee8021xConfigs{ieee8021xCfgEAPTLS, ieee8021xCfgPEAPv0_EAPMSCHAPv2})
		ieee8021xCfgEAPTLS.ProfileName = orig8021xName
		wifiCfgWPA8021xEAPTLS.Ieee8021xProfileName = ieee8021xCfgEAPTLS.ProfileName
	})
}

func TestVerifyMatchingIeee8021xConfig(t *testing.T) {
	name := "profileName"
	f := Flags{}
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, config.Ieee8021xConfig{})
	t.Run("expect MissingOrInvalidConfiguration with missing configuration", func(t *testing.T) {
		f2 := Flags{}
		rc := f2.verifyMatchingIeee8021xConfig("")
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if no matching profile", func(t *testing.T) {
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing username", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].ProfileName = name
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing ClientCert", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].Username = "UserName"
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing CACert", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].ClientCert = "AABBCCDDEEFF"
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing PrivateKey", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].CACert = "AABBCCDDEEFF"
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing PskPassphrase", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].PrivateKey = "AABBCCDDEEFF"
		f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = int(models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2)
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect Success", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = int(models.AuthenticationProtocolEAPTLS)
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.Success, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration for unsupported AuthenticationProtocolEAPTTLS_MSCHAPv2", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = int(models.AuthenticationProtocolEAPTTLS_MSCHAPv2)
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
}

func TestInvalidAuthenticationMethods(t *testing.T) {
	f := Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	cases := []struct {
		method models.AuthenticationMethod
	}{
		{method: models.AuthenticationMethod_Other},
		{method: models.AuthenticationMethod_OpenSystem},
		{method: models.AuthenticationMethod_SharedKey},
		{method: models.AuthenticationMethod_DMTFReserved},
		{method: models.AuthenticationMethod_WPA3_SAE},
		{method: models.AuthenticationMethod_WPA3_OWE},
		{method: models.AuthenticationMethod_VendorReserved},
		{method: 599},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("expect MissingOrInvalidConfiguration for AuthenticationProtocol %d", tc.method),
			func(t *testing.T) {
				f.LocalConfig.WifiConfigs[0].AuthenticationMethod = int(tc.method)
				rc := f.verifyWifiConfigurations()
				assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
			})
	}
}

func TestInvalidEncryptionMethods(t *testing.T) {
	f := Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	cases := []struct {
		method models.EncryptionMethod
	}{
		{method: models.EncryptionMethod_Other},
		{method: models.EncryptionMethod_WEP},
		{method: models.EncryptionMethod_None},
		{method: models.EncryptionMethod_DMTFReserved},
		{method: 599},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("expect MissingOrInvalidConfiguration for AuthenticationProtocol %d", tc.method),
			func(t *testing.T) {
				f.LocalConfig.WifiConfigs[0].EncryptionMethod = int(tc.method)
				rc := f.verifyWifiConfigurations()
				assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
			})
	}
}

func TestInvalidAuthenticationProtocols(t *testing.T) {
	f := Flags{}
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
	cases := []struct {
		protocol models.AuthenticationProtocol
	}{
		{protocol: models.AuthenticationProtocolEAPTTLS_MSCHAPv2},
		{protocol: models.AuthenticationProtocolPEAPv1_EAPGTC},
		{protocol: models.AuthenticationProtocolEAPFAST_MSCHAPv2},
		{protocol: models.AuthenticationProtocolEAPFAST_GTC},
		{protocol: models.AuthenticationProtocolEAP_MD5},
		{protocol: models.AuthenticationProtocolEAP_PSK},
		{protocol: models.AuthenticationProtocolEAP_SIM},
		{protocol: models.AuthenticationProtocolEAP_AKA},
		{protocol: models.AuthenticationProtocolEAPFAST_TLS},
		{protocol: 599},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("expect MissingOrInvalidConfiguration for AuthenticationProtocol %d", tc.protocol),
			func(t *testing.T) {
				f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = int(tc.protocol)
				rc := f.verifyIeee8021xConfig(f.LocalConfig.Ieee8021xConfigs[0])
				assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
			})
	}
}
