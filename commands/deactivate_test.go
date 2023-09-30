package commands

import (
	"testing"

	// "github.com/spf13/cobra"
)

func TestDeactivateRemoteCommand(t *testing.T) {
	tests := []struct {
		name          string
		flags         map[string]string
		expectedError bool
	}{
		{
			name:          "Valid flags with remote sub-command and URL",
			flags:         map[string]string{"amtPassword": "test", "url": "ws://example.com"},
			expectedError: false,
		},
		// {
		// 	name:          "Missing URL flag",
		// 	flags:         map[string]string{"amtPassword": "test"},
		// 	expectedError: true,
		// },
		// {
		// 	name:          "Missing AMT password flag",
		// 	flags:         map[string]string{"url": "ws://example.com"},
		// 	expectedError: true,
		// },
		// {
		// 	name:          "Missing both URL and AMT password flags",
		// 	flags:         map[string]string{},
		// 	expectedError: true,
		// },
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := createDeactivateCommand()

			// Set the root command name
			cmd.Use = "deactivate"

			// Set the subcommand name
			cmd.SetArgs([]string{"remote"})

			for flagName, flagValue := range test.flags {
				cmd.Flags().Set(flagName, flagValue)
			}

			err := cmd.Execute()
			if test.expectedError && err == nil {
				t.Error("Expected an error, but got nil")
			} else if !test.expectedError && err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			}
		})
	}
}
