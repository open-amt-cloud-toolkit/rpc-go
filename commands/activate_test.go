package commands

import (
	"errors"
	// "fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestRunLocalActivate(t *testing.T) {
	testCases := []struct {
		name                string
		ccmMode             bool
		acmMode             bool
		configPathOrString  string
		amtPassword         string
		provisioningCert    string
		provisioningCertPwd string
		nocertverification  bool
		verbose             bool
		expectedError       error
	}{
		{
			name:          "Neither CCM nor ACM",
			ccmMode:       false,
			acmMode:       false,
			expectedError: errors.New("Please specify a mode for activation (either --ccm or --acm)."),
		},
		{
			name:          "Both CCM and ACM",
			ccmMode:       false,
			acmMode:       false,
			expectedError: errors.New("Please specify a mode for activation (either --ccm or --acm)."),
		},
		{
			name:          "CCM mode without amtPassword",
			ccmMode:       true,
			expectedError: errors.New("For CCM activation, -amtPassword is required."),
		},
		{
			name:          "ACM mode without config and credentials",
			acmMode:       true,
			expectedError: errors.New("For ACM activation, either provide -config or specify -amtPassword, -provisioningCert, and -provisioningCertPwd."),
		},
		// {
		// 	name:               "ACM mode with config",
		// 	acmMode:            true,
		// 	configPathOrString: "../../config.json",
		// },
		// {
		// 	name:                "ACM mode with credentials",
		// 	acmMode:             true,
		// 	amtPassword:         "test",
		// 	provisioningCert:    "your provisioning certificate",
		// 	provisioningCertPwd: "test",
		// },
		// {
		// 	name:        "Valid CCM mode activation",
		// 	ccmMode:     true,
		// 	amtPassword: "password",
		// },
		// {
		// 	name:               "Valid ACM mode activation with config",
		// 	acmMode:            true,
		// 	configPathOrString: "../../config.json",
		// 	expectError:        false,
		// },
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().Bool("ccm", tc.ccmMode, "")
			cmd.Flags().Bool("acm", tc.acmMode, "")
			cmd.Flags().String("config", tc.configPathOrString, "")
			cmd.Flags().String("amtPassword", tc.amtPassword, "")
			cmd.Flags().String("provisioningCert", tc.provisioningCert, "")
			cmd.Flags().String("provisioningCertPwd", tc.provisioningCertPwd, "")
			cmd.Flags().Bool("nocertverification", tc.nocertverification, "")
			cmd.Flags().Bool("verbose", tc.verbose, "")

			err := runLocalActivate(cmd, nil)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestReadConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    ACMSettings
		expectedErr error
	}{
		{
			name:  "YAMLFile",
			input: "../../config.yaml",
			expected: ACMSettings{
				AMTPassword:         "test",
				ProvisioningCert:    "your provisioning certificate",
				ProvisioningCertPwd: "test",
			},
			expectedErr: nil,
		},
		{
			name:  "YAMLString",
			input: "amtPassword: test\nprovisioningCert: your provisioning certificate\nprovisioningCertPwd: test",
			expected: ACMSettings{
				AMTPassword:         "test",
				ProvisioningCert:    "your provisioning certificate",
				ProvisioningCertPwd: "test",
			},
			expectedErr: nil,
		},
		{
			name:  "JSONFile",
			input: "../../config.json",
			expected: ACMSettings{
				AMTPassword:         "test",
				ProvisioningCert:    "your provisioning certificate",
				ProvisioningCertPwd: "test",
			},
			expectedErr: nil,
		},
		{
			name:  "JSONString",
			input: `{"amtPassword": "test", "provisioningCert": "your provisioning certificate", "provisioningCertPwd": "test"}`,
			expected: ACMSettings{
				AMTPassword:         "test",
				ProvisioningCert:    "your provisioning certificate",
				ProvisioningCertPwd: "test",
			},
			expectedErr: nil,
		},
		{
			name:        "InvalidFormat",
			input:       "config.txt",
			expectedErr: errors.New("Invalid configuration format or file extension"),
		},
		{
			name:        "InvalidJSON",
			input:       "invalid_json_string",
			expectedErr: errors.New("Invalid configuration format or file extension"),
		},
		{
			name:        "InvalidYAML",
			input:       "invalid: yaml: string",
			expectedErr: errors.New("Invalid configuration format or file extension"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := readConfig(tt.input)
			assert.Equal(t, tt.expectedErr, err)
			if err == nil && settings != tt.expected {
				t.Errorf("Expected settings: %v, Got settings: %v", tt.expected, settings)
			}
		})
	}
}
