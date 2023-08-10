package flags

import (
	"rpc/internal/config"
	"rpc/pkg/utils"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleConfigureCommand(t *testing.T) {
	cmdLine := "rpc configure addwifisettings --config ../../config-wifi.yaml "
	args := strings.Fields(cmdLine)
	flags := NewFlags(args)
	gotResult := flags.ParseFlags()
	assert.Equal(t, flags.Local, true)
	assert.Equal(t, utils.Success, gotResult)
	assert.Equal(t, utils.CommandConfigure, flags.Command)
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
