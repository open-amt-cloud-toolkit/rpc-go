package local

import (
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigure(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect error for unhandled Subcommand", func(t *testing.T) {
		lps := setupService(&flags.Flags{})
		err := lps.Configure()
		assert.Equal(t, utils.IncorrectCommandLineParameters, err)
	})
	t.Run("expect error for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandAddWifiSettings
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.Configure()
		assert.Error(t, err)
		errEnableWiFi = nil
	})
	t.Run("expect success for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandAddWifiSettings
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
	})
	t.Run("expect error for SubCommandEnableWifiPort", func(t *testing.T) {
		f.SubCommand = utils.SubCommandEnableWifiPort
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.Configure()
		assert.Error(t, err)
		errEnableWiFi = nil
	})
	t.Run("expect success for SubCommandEnableWifiPort", func(t *testing.T) {
		f.SubCommand = utils.SubCommandEnableWifiPort
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
	})
	t.Run("expect error for SetMebx", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSetMEBx
		lps := setupService(f)
		mockSetupAndConfigurationErr = errTestError
		err := lps.Configure()
		assert.Error(t, err)
		mockSetupAndConfigurationErr = nil
	})
	t.Run("expect success for SetMebx", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSetMEBx
		lps := setupService(f)
		mockControlMode = 2
		err := lps.Configure()
		assert.NoError(t, err)
	})
	t.Run("expect error for Syncclock", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSyncClock
		lps := setupService(f)
		mockGetLowAccuracyTimeSynchErr = errTestError
		err := lps.Configure()
		assert.Error(t, err)
		mockGetLowAccuracyTimeSynchErr = nil
	})
	t.Run("expect success for Syncclock", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSyncClock
		lps := setupService(f)
		mockControlMode = 2
		err := lps.Configure()
		assert.NoError(t, err)
	})
}
