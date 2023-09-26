package commands

import (
	// "errors"
	"testing"

	"github.com/spf13/cobra"
)

// Define a helper function to create a test command
func createTestCommand() *cobra.Command {
	cmd := &cobra.Command{}

	// Add flags to the test command
	cmd.Flags().String("config", "", "config file")
	cmd.Flags().String("configJSON", "", "JSON config string")
	cmd.Flags().String("configYAML", "", "YAML config string")

	cmd.Flags().String("amtPassword", "", "AMT password")

	cmd.Flags().String("profileName", "", "profileName")
	cmd.Flags().Int("priority", 0, "priority")
	cmd.Flags().Int("authenticationMethod", 0, "authenticationMethod")
	cmd.Flags().Int("encryptionMethod", 0, "encryptionMethod")
	cmd.Flags().String("pskPassphrase", "", "PSK passphrase")
	cmd.Flags().String("ssid", "", "ssid")

	cmd.Flags().String("ieee8021xProfileName", "", "IEEE 802.1x profile name")
	cmd.Flags().String("username", "", "username")
	cmd.Flags().String("password", "", "password")
	cmd.Flags().Int("authenticationProtocol", 0, "authentication protocol")
	cmd.Flags().String("clientCert", "", "client certificate")
	cmd.Flags().String("caCert", "", "CA certificate")
	cmd.Flags().String("privateKey", "", "private key")

	return cmd
}

func TestRunAddWifiSettings(t *testing.T) {
	tests := []struct {
		name          string
		flags         map[string]string
		expectedError error
	}{
		// {
		// 	name: "AMT password is not provided",
		// 	flags: map[string]string{
		// 		"config": "../../config.yaml",
		// 	},
		// 	expectedError: errors.New("amtPassword is required"),
		// },
		// {
		// 	name: "Config file provided with valid values",
		// 	flags: map[string]string{
		// 		"amtPassword": "P@ssw0rd",
		// 		"config":      "../../config.yaml",
		// 	},
		// 	expectedError: nil,
		// },
		// {
		// 	name: "Json string provided with valid values",
		// 	flags: map[string]string{
		// 		"amtPassword": "P@ssw0rd",
		// 		"configJSON":  `{"wifiConfigs":[{"profileName":"exampleWifiWPA2","ssid":"exampleSSID","priority":1,"authenticationMethod":6,"encryptionMethod":4,"pskPassphrase":"example123!@#","ieee8021xProfileName":""},{"profileName":"exampleWifiWPA","ssid":"exampleSSID","priority":2,"authenticationMethod":4,"encryptionMethod":4,"pskPassphrase":"","ieee8021xProfileName":""},{"profileName":"exampleWifi8021xTLS","ssid":"ssid","priority":2,"authenticationMethod":7,"encryptionMethod":4,"pskPassphrase":"","ieee8021xProfileName":"exampleIeee8021xEAP-TLS"}],"ieee8021xConfigs":[{"profileName":"exampleIeee8021xEAP-TLS","username":"exampleUserName","authenticationProtocol":0,"clientCert":"testClientCertString","caCert":"testCaCertString","privateKey":""},{"profileName":"exampleIeee8021xMSCHAPv2","username":"exampleUserName","password":"","authenticationProtocol":2,"caCert":"testCaCertString"}]}`,
		// 	},
		// 	expectedError: nil,
		// },
		// TODO{
		// 	name: "yaml string provided with valid values",
		// 	flags: map[string]string{
		// 		"amtPassword": "P@ssw0rd",
		// 		"config": `wifiConfigs: [{"profileName": "exampleWifiWPA2", "ssid": "exampleSSID", "priority": 1, "authenticationMethod": 6, "encryptionMethod": 4, "pskPassphrase": "example123!@#", "ieee8021xProfileName": ""}, {"profileName": "exampleWifiWPA", "ssid": "exampleSSID", "priority": 2, "authenticationMethod": 4, "encryptionMethod": 4, "pskPassphrase": "", "ieee8021xProfileName": ""}, {"profileName": "exampleWifi8021xTLS", "ssid": "ssid", "priority": 2, "authenticationMethod": 7, "encryptionMethod": 4, "pskPassphrase": "", "ieee8021xProfileName": "exampleIeee8021xEAP-TLS"}]\nieee8021xConfigs: [{"profileName": "exampleIeee8021xEAP-TLS", "username": "exampleUserName", "authenticationProtocol": 0, "clientCert": "testClientCertString", "caCert": "testCaCertString", "privateKey": ""}, {"profileName": "exampleIeee8021xMSCHAPv2", "username": "exampleUserName", "password": "", "authenticationProtocol": 2, "caCert": "testCaCertString"}]
		// 		`,
		// 	},
		// 	expectedError: nil,
		// },
		{
			name: "Valid values provided for authentication method 6",
			flags: map[string]string{
				"amtPassword":            "P@ssw0rd",
				"profileName":            "exampleWifiWPA2",
				"ssid":                   "exampleSSID",
				"priority":               "1",
				"authenticationMethod":   "6",
				"encryptionMethod":       "3",
				"pskPassphrase":          "example123!@#",
			},
			expectedError: nil,
		},
		{
			name: "Valid values provided for authentication method 7",
			flags: map[string]string{
				"amtPassword":            "P@ssw0rd",
				"profileName":            "exampleWifiWPA2",
				"ssid":                   "exampleSSID",
				"priority":               "1",
				"authenticationMethod":   "7",
				"encryptionMethod":       "4",
				"ieee8021xProfileName":   "profileName",
				"username":               "username",
				"password":				  "password",
				"authenticationProtocol": "2",
				"clientCert":             "clientCert",
				"caCert":                 "caCert",
				"privateKey":             "privateKey",
			},
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := createTestCommand()

			// Set flags based on the test case
			for flag, value := range test.flags {
				cmd.Flags().Set(flag, value)
			}

			// Call the function and check the error
			err := runAddWifiSettings(cmd, []string{})
			if (err == nil && test.expectedError != nil) || (err != nil && test.expectedError == nil) {
				t.Fatalf("Expected error: %v, Got error: %v", test.expectedError, err)
			}

			if err != nil && err.Error() != test.expectedError.Error() {
				t.Fatalf("Expected error message: %v, Got: %v", test.expectedError, err)
			}
		})
	}
}
