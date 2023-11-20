package local

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"rpc/internal/amt"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
)

func TestOpState(t *testing.T) {

	tests := []struct {
		name             string
		expectedRC       utils.ReturnCode
		rsp              amt.ChangeEnabledResponse
		errChangeEnabled error
		errEnableAMT     error
		errDisableAMT    error
		disableFlag      bool
		enableFlag       bool
	}{
		{
			name:             "expect AMTConnectionFailed",
			expectedRC:       utils.AMTConnectionFailed,
			errChangeEnabled: mockStandardErr,
		},
		{
			name:        "expect noop for older versions",
			expectedRC:  utils.Success,
			rsp:         ChangeEnabledResponseNotNew,
			disableFlag: true,
		},
		{
			name:        "expect noop for disable if already disabled",
			expectedRC:  utils.Success,
			rsp:         ChangeEnabledResponseNewDisabled,
			disableFlag: true,
		},
		{
			name:          "expect AmtNotReady for disable if error occurs",
			expectedRC:    utils.AmtNotReady,
			rsp:           ChangeEnabledResponseNewEnabled,
			errDisableAMT: mockStandardErr,
			disableFlag:   true,
		},
		{
			name:        "expect succes for disable happy path",
			expectedRC:  utils.Success,
			rsp:         ChangeEnabledResponseNewEnabled,
			disableFlag: true,
		},
		{
			name:       "expect noop for enable if already enabled",
			expectedRC: utils.Success,
			rsp:        ChangeEnabledResponseNewEnabled,
			enableFlag: true,
		},
		{
			name:         "expect AmtNotReady for enable if error occurs",
			expectedRC:   utils.AmtNotReady,
			rsp:          ChangeEnabledResponseNewDisabled,
			errEnableAMT: mockStandardErr,
			enableFlag:   true,
		},
		{
			name:       "expect succes for enable happy path",
			expectedRC: utils.Success,
			rsp:        ChangeEnabledResponseNewDisabled,
			enableFlag: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origChangeEnabledErr := mockChangeEnabledErr
			mockChangeEnabledErr = tc.errChangeEnabled
			origDisableAMTErr := mockDisableAMTErr
			mockDisableAMTErr = tc.errDisableAMT
			origEnableAMTErr := mockEnableAMTErr
			mockEnableAMTErr = tc.errEnableAMT
			origRsp := mockChangeEnabledResponse
			mockChangeEnabledResponse = tc.rsp
			f := &flags.Flags{}
			f.OpStateFlags.Disable = tc.disableFlag
			f.OpStateFlags.Enable = tc.enableFlag
			lps := setupService(f)
			rc := lps.OpState()
			assert.Equal(t, tc.expectedRC, rc)
			mockChangeEnabledResponse = origRsp
			mockChangeEnabledErr = origChangeEnabledErr
			mockEnableAMTErr = origEnableAMTErr
			mockDisableAMTErr = origDisableAMTErr
		})
	}
}

func TestCheckAndEnableAMT(t *testing.T) {

	tests := []struct {
		name             string
		skipIPRenewal    bool
		expectedRC       utils.ReturnCode
		rsp              amt.ChangeEnabledResponse
		errChangeEnabled error
		errEnableAMT     error
		errDisableAMT    error
		renewDHCPLeaseRC utils.ReturnCode
	}{
		{
			name:             "expect AMTConnectionFailed",
			expectedRC:       utils.AMTConnectionFailed,
			errChangeEnabled: mockStandardErr,
		},
		{
			name:       "expect noop for older versions",
			expectedRC: utils.Success,
			rsp:        ChangeEnabledResponseNotNew,
		},
		{
			name:       "expect noop if already enabled",
			expectedRC: utils.Success,
			rsp:        ChangeEnabledResponseNewEnabled,
		},
		{
			name:         "expect AmtNotReady for enable if error occurs",
			expectedRC:   utils.AmtNotReady,
			rsp:          ChangeEnabledResponseNewDisabled,
			errEnableAMT: mockStandardErr,
		},
		{
			name:       "expect Success for enable happy path",
			expectedRC: utils.Success,
			rsp:        ChangeEnabledResponseNewDisabled,
		},
		{
			name:             "expect Success if skipIPRenewal is true",
			expectedRC:       utils.Success,
			rsp:              ChangeEnabledResponseNewDisabled,
			skipIPRenewal:    true,
			renewDHCPLeaseRC: utils.NetworkConfigurationFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origChangeEnabledErr := mockChangeEnabledErr
			mockChangeEnabledErr = tc.errChangeEnabled
			origDisableAMTErr := mockDisableAMTErr
			mockDisableAMTErr = tc.errDisableAMT
			origEnableAMTErr := mockEnableAMTErr
			mockEnableAMTErr = tc.errEnableAMT
			origRsp := mockChangeEnabledResponse
			mockChangeEnabledResponse = tc.rsp
			origRenewDHCPLeaseRC := mockRenewDHCPLeaseRC
			mockRenewDHCPLeaseRC = tc.renewDHCPLeaseRC
			f := &flags.Flags{}
			lps := setupService(f)
			rc := lps.CheckAndEnableAMT(tc.skipIPRenewal)
			assert.Equal(t, tc.expectedRC, rc)
			mockChangeEnabledResponse = origRsp
			mockChangeEnabledErr = origChangeEnabledErr
			mockEnableAMTErr = origEnableAMTErr
			mockDisableAMTErr = origDisableAMTErr
			mockRenewDHCPLeaseRC = origRenewDHCPLeaseRC
		})
	}
}

func TestRenewIP(t *testing.T) {
	f := &flags.Flags{}
	log.SetLevel(log.DebugLevel)
	lps := setupService(f)
	origRC := mockRenewDHCPLeaseRC
	mockRenewDHCPLeaseRC = utils.NetworkConfigurationFailed
	rc := lps.RenewIP()
	assert.Equal(t, mockRenewDHCPLeaseRC, rc)
	mockRenewDHCPLeaseRC = origRC
}
