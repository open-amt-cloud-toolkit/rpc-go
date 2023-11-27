package flags

import (
	"github.com/stretchr/testify/assert"
	"rpc/pkg/utils"
	"strings"
	"testing"
)

func TestParseFlagsAmtInfo(t *testing.T) {
	defaultFlags := AmtInfoFlags{
		Ver:      true,
		Bld:      true,
		Sku:      true,
		UUID:     true,
		Mode:     true,
		DNS:      true,
		Ras:      true,
		Lan:      true,
		Hostname: true,
		OpState:  true,
	}

	tests := map[string]struct {
		cmdLine    string
		wantResult utils.ReturnCode
		wantFlags  AmtInfoFlags
		userInput  string
	}{
		"expect success for basic command": {
			cmdLine:    "./rpc amtinfo -json",
			wantResult: utils.Success,
			wantFlags:  defaultFlags,
		},
		"expect IncorrectCommandLineParameters on Parse error": {
			cmdLine:    "./rpc amtinfo -balderdash",
			wantResult: utils.IncorrectCommandLineParameters,
			wantFlags:  AmtInfoFlags{},
		},
		"expect only cert flag with no password on command line": {
			cmdLine:    "./rpc amtinfo -cert",
			wantResult: utils.Success,
			wantFlags: AmtInfoFlags{
				Cert: true,
			},
		},
		"expect both cert flags with no password on command line": {
			cmdLine:    "./rpc amtinfo -cert -password testPassword",
			wantResult: utils.Success,
			wantFlags: AmtInfoFlags{
				Cert:     true,
				UserCert: true,
			},
		},
		"expect success for userCert with no password": {
			cmdLine:    "./rpc amtinfo -userCert",
			wantResult: utils.Success,
			wantFlags: AmtInfoFlags{
				UserCert: true,
			},
		},
		"expect Success for userCert with password": {
			cmdLine:    "./rpc amtinfo -userCert -password testPassword",
			wantResult: utils.Success,
			wantFlags: AmtInfoFlags{
				UserCert: true,
			},
		},
		"expect Success for userCert with password input": {
			cmdLine:    "./rpc amtinfo -userCert",
			wantResult: utils.Success,
			wantFlags: AmtInfoFlags{
				UserCert: true,
			},
			userInput: "testPassword",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			if tc.userInput != "" {
				defer userInput(t, tc.userInput)()
			}
			flags := NewFlags(args)
			gotResult := flags.ParseFlags()
			assert.Equal(t, tc.wantResult, gotResult)
			assert.Equal(t, true, flags.Local)
			assert.Equal(t, utils.CommandAMTInfo, flags.Command)
			assert.Equal(t, tc.wantFlags, flags.AmtInfo)
		})
	}
}
