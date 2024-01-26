package activate

import (
	"strconv"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestRunLocalActivateCmd(t *testing.T) {
	testCases := []struct {
		name          string
		ccmMode       bool
		acmMode       bool
		flags         map[string]string
		viperPassword string
		expectError   bool
		errorMsg      string
	}{
		{
			name: "Conflicting Modes",
		    ccmMode: true,
		    acmMode: true,
			flags: map[string]string{},
			expectError: true,
		    errorMsg: "You cannot activate in both CCM and ACM modes simultaneously.",
		},
		{
			name: "No Mode Specified",
		    ccmMode:     false,
		    acmMode:     false,
			flags: map[string]string{},
			expectError: true,
			errorMsg:    "Please specify a mode for activation (either --ccm or --acm).",
		},
		{
			name: "Valid CCM Mode",
		    ccmMode: true,
		    acmMode: false,
			flags: map[string]string{
				"amtPassword": "valid_password",
			},
			expectError: false,
		},
		// { TODO:
		// 	name: "Valid CCM Mode",
		//     ccmMode: true,
		//     acmMode: false,
		// 	flags: map[string]string{
		// 		"amtPassword": "",
		// 	},
		//     viperPassword: "valid_password",
		// 	expectError: false,
		// },
		{
			name: "Valid ACM Mode with YAML file",
		    ccmMode:     false,
		    acmMode:     true,
			flags: map[string]string{
				"config":     "../../config.yaml",
			},
			expectError: false,
		},
		{
			name:    "Valid ACM Mode with YAML string",
			ccmMode: false,
			acmMode: true,
			flags: map[string]string{
				"configYAML": "amtPassword: test\nprovisioningCert: your provisioning certificate\nprovisioningCertPwd: test",
			},
			expectError: false,
		},
		{
			name:    "Valid ACM Mode with JSON string",
			ccmMode: false,
			acmMode: true,
			flags: map[string]string{
				"configJSON": `{"amtPassword": "test", "provisioningCert": "your provisioning certificate", "provisioningCertPwd": "test"}`,
			},
			expectError: false,
		},
		{
			name:    "Valid ACM Mode",
			ccmMode: false,
			acmMode: true,
			flags: map[string]string{
				"amtPassword": "test", 
				"provisioningCert": "your provisioning certificate", 
				"provisioningCertPwd": "test",
			},
			expectError: false,
		},
		{
			name:    "No amtPassword for ACM Mode",
			ccmMode: false,
			acmMode: true,
			flags: map[string]string{
				"provisioningCert": "your provisioning certificate", 
				"provisioningCertPwd": "test",
			},
			expectError: true,
			errorMsg: "Missing required flags for ACM activation: -amtPassword. Alternatively, provide a configuration using -config, -configJSON, or -configYAML", 
		},
		{
			name:    "No amtPassword for ACM Mode",
			ccmMode: false,
			acmMode: true,
			flags: map[string]string{
				"amtPassword": "test", 
			},
			expectError: true,
			errorMsg: "Missing required flags for ACM activation: -provisioningCert, -provisioningCertPwd. Alternatively, provide a configuration using -config, -configJSON, or -configYAML", 
		},
		// {
		// 	name:    "Invalid ACM Mode with JSON string",
		// 	ccmMode: false,
		// 	acmMode: true,
		// 	flags: map[string]string{
		// 		"configJSON": `{"provisioningCert": "your provisioning certificate", "provisioningCertPwd": "test"}`,
		// 	},
		// 	expectError: true,
		// 	errorMsg: "One or more required configurations are missing",
		// },
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			
			viper.Reset()

			cmd := &cobra.Command{}
			cmd.Flags().BoolP("ccm", "", false, "Activate in CCM mode")
			cmd.Flags().BoolP("acm", "", false, "Activate in ACM mode")
			cmd.Flags().StringP("config", "", "", "Path to the configuration file or JSON/YAML string (required for ACM mode if no -amtPassword and -provisioningCert and -provisioningCertPwd are provided)")
			cmd.Flags().StringP("configJSON", "", "", "Configuration as a JSON string")
			cmd.Flags().StringP("configYAML", "", "", "Configuration as a YAML string")
			cmd.Flags().StringP("amtPassword", "", "", "AMT Password (required for CCM and ACM mode or if no -config is provided)")
			cmd.Flags().StringP("provisioningCert", "", "", "Provisioning Certificate (required for ACM mode or if no -config is provided)")
			cmd.Flags().StringP("provisioningCertPwd", "", "", "Provisioning Certificate Password (required for CCM mode or if no -config is provided)")
			cmd.Flags().BoolP("nocertverification", "n", false, "Disable certificate verification")

			cmd.Flags().Set("ccm", strconv.FormatBool(tc.ccmMode))
			cmd.Flags().Set("acm", strconv.FormatBool(tc.acmMode))

			for key, value := range tc.flags {
				err := cmd.Flags().Set(key, value)
				assert.NoError(t, err)
			}

			err := runLocalActivate(cmd, []string{})
			if tc.expectError {
				if err.Error() != tc.errorMsg {
					t.Errorf("%s: expected error message '%s', got '%s'", tc.name, tc.errorMsg, err.Error())
				}
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
