package local

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
)

func TestDeactivation(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	stdErr := errors.New("yep it failew")

	t.Run("should return AMTConnectionFailed when GetControlMode fails", func(t *testing.T) {
		lps := setupService(f)
		mockControlModeErr = stdErr
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.AMTConnectionFailed, resultCode)
		mockControlModeErr = nil
	})

	t.Run("should return UnableToDeactivate when already deactivated", func(t *testing.T) {
		lps := setupService(f)
		// this is default mode for the mock already
		// mockControlMode = 0
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.UnableToDeactivate, resultCode)
	})

	t.Run("should return DeactivationFailed if Unprovision fails", func(t *testing.T) {
		lps := setupService(f)
		mockControlMode = 1
		mockUnprovisionErr = stdErr
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, resultCode)
		mockControlMode = 0
		mockUnprovisionErr = nil
	})

	t.Run("should return Success for CCM happy path", func(t *testing.T) {
		lps := setupService(f)
		mockControlMode = 1
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.Success, resultCode)
		mockControlMode = 0
	})

	t.Run("should return DeactivationFailed for ACM", func(t *testing.T) {
		lps := setupService(f)
		// this is default mode for the mock already
		mockControlMode = 2
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, resultCode)
	})
}
