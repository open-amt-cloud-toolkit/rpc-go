package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateDeactivateCommand(t *testing.T) {
	tests := []struct {
		name          string
		flags         map[string]string
		expectedError bool
	}{
		{
			name:          "Valid flags",
			flags:         map[string]string{"password": "test"},
			expectedError: false,
		},
		{
			name:          "Missing password flag",
			flags:         map[string]string{},
			expectedError: true,
		},
		{
			name:          "Valid flags with remote sub-command and URL",
			flags:         map[string]string{"password": "test", "url": "ws://example.com"},
			expectedError: false,
		},
		{
			name:          "Missing URL flag for remote sub-command",
			flags:         map[string]string{"password": "test"},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := createDeactivateCommand()

			// Simulate setting the flags based on the test case
			for flagName, value := range tt.flags {
				cmd.Flags().Set(flagName, value)
			}
			// Manually parse the flags
			err := cmd.ParseFlags([]string{})

			// Check for errors in flag parsing
			assert.NoError(t, err, "Expected no error while parsing flags")

			// Execute the PersistentPreRunE hook
			preRunErr := cmd.PersistentPreRunE(cmd, []string{})

			// Check the error condition
			if tt.expectedError {
				assert.Error(t, preRunErr, "Expected an error but got nil")
			} else {
				assert.NoError(t, preRunErr, "Expected no error but got %v", preRunErr)
			}
		})
	}
}
