package deactivate

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestRunRemoteDeactivate(t *testing.T) {
	tests := []struct {
		name            string
		urlFlag         string
		amtPasswordFlag string
		wantErr         bool
		errorMessage    string
	}{
		{
			name:            "Missing URL",
			urlFlag:         "",
			amtPasswordFlag: "password",
			wantErr:         true,
			errorMessage:    "url is required",
		},
		{
			name:            "Missing AMT Password",
			urlFlag:         "wss://example.com",
			amtPasswordFlag: "",
			wantErr:         true,
			errorMessage:    "AMT password is required",
		},
		{
			name:            "All Flags Provided",
			urlFlag:         "wss://example.com",
			amtPasswordFlag: "password",
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().StringP("url", "u", "", "Websocket address of server to activate against")
			cmd.Flags().StringP("amtPassword", "p", "", "AMT Password")
			_ = cmd.Flags().Set("url", tt.urlFlag)
			_ = cmd.Flags().Set("amtPassword", tt.amtPasswordFlag)

			err := runRemoteDeactivate(cmd, nil)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, err.Error(), tt.errorMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
