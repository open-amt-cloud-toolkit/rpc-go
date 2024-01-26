package activate

import (
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRunRemoteActivateCmd(t *testing.T) {
	testCases := []struct {
		name        string
		flags       map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid Flags",
			flags: map[string]string{
				"url":      "wss://example.com",
				"profile":  "defaultProfile",
				"uuid":     "4c4c4544-004d-4d10-8050-b3c04f325133",
				"name":     "TestDevice",
				"dns":      "example.com",
				"hostname": "testhost",
			},
			expectError: false,
		},
		{
			name: "Missing URL",
			flags: map[string]string{
				"profile": "defaultProfile",
			},
			expectError: true,
			errorMsg:    "-u flag is required and cannot be empty",
		},
		{
			name: "Missing Profile",
			flags: map[string]string{
				"url": "wss://example.com",
			},
			expectError: true,
			errorMsg:    "-profile flag is required and cannot be empty",
		},
		{
			name: "Invalid UUID",
			flags: map[string]string{
				"url":     "wss://example.com",
				"profile": "defaultProfile",
				"uuid":    "4c4c4544-004d-4d10",
			},
			expectError: true,
			errorMsg:    "uuid provided does not follow proper uuid format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().StringP("url", "u", "", "Websocket address of server to activate against")
			cmd.Flags().StringP("profile", "p", "", "Name of the profile to use")
			cmd.Flags().String("uuid", "", "override AMT device uuid for use with non-CIRA workflow")
			cmd.Flags().String("name", "", "friendly name to associate with this device")
			cmd.Flags().StringP("dns", "d", "", "dns suffix override")
			cmd.Flags().StringP("hostname", "", "", "hostname override")
			cmd.Flags().BoolP("nocertverification", "n", false, "Disable certificate verification")

			for key, value := range tc.flags {
				err := cmd.Flags().Set(key, value)
				assert.NoError(t, err)
			}

			err := runRemoteActivate(cmd, []string{})
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
