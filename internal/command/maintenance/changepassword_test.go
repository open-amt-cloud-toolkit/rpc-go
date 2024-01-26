package maintenance

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestRunChangePassword(t *testing.T) {
	tests := []struct {
		name           string
		staticFlag     string
		amtPasswordFlag string
		viperPassword  string
		wantErr        bool
		wantSetStatic  bool
	}{
		{
			name:           "No AMT Password Provided",
			staticFlag:     "newpassword123",
			amtPasswordFlag: "",
			viperPassword:  "",
			wantErr:        true,
			wantSetStatic:  false,
		},
		{
			name:           "AMT Password Provided via Flag",
			staticFlag:     "newpassword123",
			amtPasswordFlag: "oldpassword123",
			viperPassword:  "",
			wantErr:        false,
			wantSetStatic:  true,
		},
		{
			name:           "AMT Password Provided via Viper",
			staticFlag:     "newpassword123",
			amtPasswordFlag: "",
			viperPassword:  "oldpasswordFromViper",
			wantErr:        false,
			wantSetStatic:  true,
		},
		{
			name:           "Random Password When Static is Empty",
			staticFlag:     "",
			amtPasswordFlag: "oldpassword123",
			viperPassword:  "",
			wantErr:        false,
			wantSetStatic:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.viperPassword != "" {
				viper.Set("amtPassword", tt.viperPassword)
				defer viper.Reset()
			}

			cmd := &cobra.Command{}
			cmd.Flags().StringVarP(&amtPassword, "amtPassword", "p", "", "AMT Password")
			cmd.Flags().StringVarP(&static, "static", "s", "", "Set a new static AMT password")

			_ = cmd.Flags().Set("amtPassword", tt.amtPasswordFlag)
			_ = cmd.Flags().Set("static", tt.staticFlag)

			err := runChangePassword(cmd, nil)

			if tt.wantErr {
				assert.Error(t, err)
				assert.EqualError(t, err, "AMT password not provided")
			} else {
				assert.NoError(t, err)
				// If static flag is set, check that it matches the expected new password
				if tt.wantSetStatic {
					assert.Equal(t, tt.staticFlag, static)
				}
			}
		})
	}
}
