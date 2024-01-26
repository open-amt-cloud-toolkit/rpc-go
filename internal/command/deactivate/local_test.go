package deactivate

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestRunLocalDeactivate(t *testing.T) {
	tests := []struct {
		name          string
		amtPassword   string
		viperPassword string
		wantErr       bool
	}{
		{
			name:          "Missing AMT Password with Viper not providing it",
			amtPassword:   "",
			viperPassword: "",
			wantErr:       true,
		},
		{
			name:          "Missing AMT Password with Viper providing it",
			amtPassword:   "",
			viperPassword: "password123",
			wantErr:       false,
		},
		{
			name:        "AMT Password Provided",
			amtPassword: "P@ssw0rd",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.viperPassword != "" {
				viper.Set("amtPassword", tt.viperPassword)
				defer viper.Reset()
			}

			cmd := &cobra.Command{}
			cmd.Flags().StringP("amtPassword", "p", "", "AMT Password")
			if tt.amtPassword != "" {
				_ = cmd.Flags().Set("amtPassword", tt.amtPassword)
			}

			err := runLocalDeactivate(cmd, nil)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
