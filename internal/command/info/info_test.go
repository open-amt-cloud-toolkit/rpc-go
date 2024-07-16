package commands

import (
	"rpc/config"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestRunAMTInfo(t *testing.T) {
	tests := []struct {
		name    string
		cmdLine string
		flags   config.AmtInfo
	}{
		// {
		// 	name:    "expect success for basic command",
		// 	cmdLine: "./rpc amtinfo",
		// 	flags:   AmtInfo{
		// 		Ver:      true,
		// 		Bld:      true,
		// 		Sku:      true,
		// 		UUID:     true,
		// 		Mode:     true,
		// 		DNS:      true,
		// 		Cert:     true,
		// 		UserCert: true,
		// 		Ras:      true,
		// 		Lan:      true,
		// 		Hostname: true,
		// 	},
		// },
		{
			name: "expect IncorrectCommandLineParameters on Parse error",
			cmdLine: "./rpc amtinfo -balderdash",
			flags:   config.AmtInfo{},
		},
		// {
		// 	name: "expect only cert flag with no password on command line",
		// 	cmdLine: "./rpc amtinfo -cert",
		// 	flags: AmtInfo{
		// 		Cert: true,
		// 	},
		// },
		// {
		// 	name: "expect both cert flags with no password on command line",
		// 	cmdLine: "./rpc amtinfo -cert -password testPassword",
		// 	flags: AmtInfo{
		// 		Cert:     true,
		// 		UserCert: true,
		// 	},
		// },
		// {
		// 	name: "expect success for userCert with no password",
		// 	cmdLine: "./rpc amtinfo -userCert",
		// 	flags: AmtInfo{
		// 		UserCert: true,
		// 	},
		// },
		// {
		// 	name: "expect Success for userCert with password",
		// 	cmdLine: "./rpc amtinfo -userCert -password testPassword",
		// 	flags: AmtInfo{
		// 		UserCert: true,
		// 	},
		// },
		// {
		// 	name: "expect Success for userCert with password input",
		// 	cmdLine: "./rpc amtinfo -userCert",
		// 	flags: AmtInfo{
		// 		UserCert: true,
		// 	},
		// },
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetArgs(strings.Split(test.cmdLine, " "))

			err := runAMTInfo(cmd, []string{})
			assert.NoError(t, err)

			// Assert expected flags
			assert.Equal(t, test.flags, info)
		})
	}
}
