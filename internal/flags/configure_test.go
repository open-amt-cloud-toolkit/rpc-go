package flags

import (
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

func TestVerifyWifiConfigurationFile(t *testing.T) {

	cases := []struct {
		description       string
		testConfiguration Flags
		expected          int
	}{
		{
			description: "Missing ProfileName",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName: "",
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Missing SSID",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName: "Test-Profile-1",
							SSID:        "",
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Missing Priority",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName: "Test-Profile-1",
							SSID:        "Test-SSID-1",
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Missing AuthenticationMethod",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName: "Test-Profile-1",
							SSID:        "Test-SSID-1",
							Priority:    1,
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Missing EncryptionMethod",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName:          "Test-Profile-1",
							SSID:                 "Test-SSID-1",
							Priority:             1,
							AuthenticationMethod: 6,
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Missing Passphrase when AuthenticationMethod is 6",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName:          "Test-Profile-1",
							SSID:                 "Test-SSID-1",
							Priority:             1,
							AuthenticationMethod: 6,
							EncryptionMethod:     4,
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Properly formed config",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName:          "Test-Profile-1",
							SSID:                 "Test-SSID-1",
							Priority:             1,
							AuthenticationMethod: 6,
							EncryptionMethod:     4,
							PskPassphrase:        "Test-Passphrase-1",
							Ieee8021xProfileName: "",
						},
					},
				},
			},
			expected: utils.Success,
		},
		{
			description: "Passphrase present when AuthenticationMethod is 5",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName:          "Test-Profile-1",
							SSID:                 "Test-SSID-1",
							Priority:             1,
							AuthenticationMethod: 5,
							EncryptionMethod:     4,
							PskPassphrase:        "Test-Passphrase-1",
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Passphrase present when AuthenticationMethod is 7",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName:          "Test-Profile-1",
							SSID:                 "Test-SSID-1",
							Priority:             1,
							AuthenticationMethod: 7,
							EncryptionMethod:     4,
							PskPassphrase:        "Test-Passphrase-1",
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Successfully matches IEEE802.1 ProfileName",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName:          "Test-Profile-1",
							SSID:                 "Test-SSID-1",
							Priority:             1,
							AuthenticationMethod: 7,
							EncryptionMethod:     4,
							PskPassphrase:        "",
							Ieee8021xProfileName: "Test-IEEE-Profile",
						},
					},
					Ieee8021xConfigs: config.Ieee8021xConfigs{
						{
							ProfileName: "Test-IEEE-Profile",
						},
					},
				},
			},
			expected: utils.Success,
		},
		{
			description: "Found duplicate IEEE802.1 ProfileName when AuthenticationMethod is 5",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName:          "Test-Profile-1",
							SSID:                 "Test-SSID-1",
							Priority:             1,
							AuthenticationMethod: 7,
							EncryptionMethod:     4,
							PskPassphrase:        "",
							Ieee8021xProfileName: "Test-IEEE-Profile",
						},
					},
					Ieee8021xConfigs: config.Ieee8021xConfigs{
						{
							ProfileName: "Test-IEEE-Profile",
						},
						{
							ProfileName: "Test-IEEE-Profile",
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Found duplicate IEEE802.1 ProfileName when AuthenticationMethod is 7",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					WifiConfigs: config.WifiConfigs{
						{
							ProfileName:          "Test-Profile-1",
							SSID:                 "Test-SSID-1",
							Priority:             1,
							AuthenticationMethod: 7,
							EncryptionMethod:     4,
							PskPassphrase:        "",
							Ieee8021xProfileName: "Test-IEEE-Profile",
						},
					},
					Ieee8021xConfigs: config.Ieee8021xConfigs{
						{
							ProfileName: "Test-IEEE-Profile",
						},
						{
							ProfileName: "Test-IEEE-Profile",
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
		{
			description: "Missing ProfileName in IEEE802.1x config",
			testConfiguration: Flags{
				LocalConfig: config.Config{
					Ieee8021xConfigs: config.Ieee8021xConfigs{
						{
							ProfileName: "",
						},
					},
				},
			},
			expected: utils.MissingOrIncorrectProfile,
		},
	}

	for _, tt := range cases {
		t.Run(tt.description, func(t *testing.T) {
			gotResult := tt.testConfiguration.verifyWifiConfigurationFile()
			if gotResult != tt.expected {
				t.Errorf("expected %d but got %d", tt.expected, gotResult)
			}
		})
	}
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
