package local

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
)

func TestDeactivation(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	stdErr := errors.New("yep it failew")

	t.Run("returns AMTConnectionFailed when GetControlMode fails", func(t *testing.T) {
		lps := setupService(f)
		mockControlModeErr = stdErr
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.AMTConnectionFailed, resultCode)
		mockControlModeErr = nil
	})

	t.Run("returns UnableToDeactivate when ControlMode is pre-provisioning (0)", func(t *testing.T) {
		lps := setupService(f)
		// this is default mode for the mock already
		// mockControlMode = 0
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.UnableToDeactivate, resultCode)
	})
}

func TestDeactivateCCM(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	mockControlMode = 1

	t.Run("returns Success for happy path", func(t *testing.T) {
		lps := setupService(f)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.Success, resultCode)
	})
	t.Run("returns DeactivationFailed when unprovision fails", func(t *testing.T) {
		mockUnprovisionErr = errors.New("test error")
		lps := setupService(f)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, resultCode)
		mockUnprovisionErr = nil
	})
	t.Run("returns DeactivationFailed when unprovision ReturnStatus is not success (0)", func(t *testing.T) {
		mockUnprovisionCode = 1
		lps := setupService(f)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, resultCode)
		mockUnprovisionCode = 0
	})
}

func TestDeactivateACM(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	mockControlMode = 2

	t.Run("returns Success for happy path", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondUnprovision(t, w)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.Success, resultCode)
	})

	t.Run("returns UnableToDeactivate on SetupAndConfigurationService.Unprovision server error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondServerError(w)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.UnableToDeactivate, resultCode)
	})
	t.Run("returns UnableToDeactivate on SetupAndConfigurationService.Unprovision xml error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondBadXML(t, w)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, resultCode)
	})
	t.Run("returns DeactivationFailed when unprovision ReturnStatus is not success (0)", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mockUnprovisionResponse.Body.Unprovision_OUTPUT.ReturnValue = 1
			respondUnprovision(t, w)
			mockUnprovisionResponse.Body.Unprovision_OUTPUT.ReturnValue = 0
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, resultCode)
	})
}
