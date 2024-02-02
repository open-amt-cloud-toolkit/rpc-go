package local

import (
	"rpc/internal/amt"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCheckAndEnableAMT(t *testing.T) {

	tests := []struct {
		name             string
		skipIPRenewal    bool
		expectedRC       error
		rsp              amt.ChangeEnabledResponse
		errChangeEnabled error
		errEnableAMT     error
		errDisableAMT    error
		renewDHCPLeaseRC error
	}{
		{
			name:             "expect AMTConnectionFailed",
			expectedRC:       utils.AMTConnectionFailed,
			errChangeEnabled: errMockStandard,
		},
		{
			name:       "expect noop for older versions",
			expectedRC: nil,
			rsp:        ChangeEnabledResponseNotNew,
		},
		{
			name:       "expect noop if already enabled",
			expectedRC: nil,
			rsp:        ChangeEnabledResponseNewEnabled,
		},
		{
			name:         "expect AmtNotReady for enable if error occurs",
			expectedRC:   utils.AmtNotReady,
			rsp:          ChangeEnabledResponseNewDisabled,
			errEnableAMT: errMockStandard,
		},
		{
			name:       "expect Success for enable happy path",
			expectedRC: nil,
			rsp:        ChangeEnabledResponseNewDisabled,
		},
		{
			name:             "expect Success if skipIPRenewal is true",
			expectedRC:       nil,
			rsp:              ChangeEnabledResponseNewDisabled,
			skipIPRenewal:    true,
			renewDHCPLeaseRC: utils.NetworkConfigurationFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origChangeEnabledErr := errMockChangeEnabled
			errMockChangeEnabled = tc.errChangeEnabled
			origDisableAMTErr := mockDisableAMTErr
			mockDisableAMTErr = tc.errDisableAMT
			origEnableAMTErr := mockEnableAMTErr
			mockEnableAMTErr = tc.errEnableAMT
			origRsp := mockChangeEnabledResponse
			mockChangeEnabledResponse = tc.rsp
			origRenewDHCPLeaseRC := mockRenewDHCPLeaseerr
			mockRenewDHCPLeaseerr = tc.renewDHCPLeaseRC
			f := &flags.Flags{}
			lps := setupService(f)
			err := lps.CheckAndEnableAMT(tc.skipIPRenewal)
			assert.Equal(t, tc.expectedRC, err)
			mockChangeEnabledResponse = origRsp
			errMockChangeEnabled = origChangeEnabledErr
			mockEnableAMTErr = origEnableAMTErr
			mockDisableAMTErr = origDisableAMTErr
			mockRenewDHCPLeaseerr = origRenewDHCPLeaseRC
		})
	}
}

func TestRenewIP(t *testing.T) {
	f := &flags.Flags{}
	log.SetLevel(log.DebugLevel)
	lps := setupService(f)
	origRC := mockRenewDHCPLeaseerr
	mockRenewDHCPLeaseerr = utils.NetworkConfigurationFailed
	err := lps.RenewIP()
	assert.Equal(t, mockRenewDHCPLeaseerr, err)
	mockRenewDHCPLeaseerr = origRC
}
