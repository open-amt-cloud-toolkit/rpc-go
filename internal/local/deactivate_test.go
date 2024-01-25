package local

import (
	"errors"
	"net/http"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeactivation(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	stdErr := errors.New("yep it failew")

	t.Run("returns AMTConnectionFailed when GetControlMode fails", func(t *testing.T) {
		lps := setupService(f)
		mockControlModeErr = stdErr
		err := lps.Deactivate()
		assert.Equal(t, utils.AMTConnectionFailed, err)
		mockControlModeErr = nil
	})

	t.Run("returns UnableToDeactivate when ControlMode is pre-provisioning (0)", func(t *testing.T) {
		lps := setupService(f)
		// this is default mode for the mock already
		// mockControlMode = 0
		err := lps.Deactivate()
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

func TestDeactivateCCM(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	mockControlMode = 1

	t.Run("returns Success without password", func(t *testing.T) {
		f.Password = ""
		lps := setupService(f)
		err := lps.Deactivate()
		assert.Equal(t, nil, err)
	})
	t.Run("returns Success with warning, given the password", func(t *testing.T) {
		f.Password = "P@ssw0rd"
		lps := setupService(f)
		err := lps.Deactivate()
		assert.Equal(t, nil, err)
	})
	t.Run("returns DeactivationFailed when unprovision fails", func(t *testing.T) {
		mockUnprovisionErr = errors.New("test error")
		lps := setupService(f)
		err := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, err)
		mockUnprovisionErr = nil
	})
	t.Run("returns DeactivationFailed when unprovision ReturnStatus is not success (0)", func(t *testing.T) {
		mockUnprovisionCode = 1
		lps := setupService(f)
		err := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, err)
		mockUnprovisionCode = 0
	})
}

func TestDeactivateACM(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	mockControlMode = 2

	// t.Run("returns Success for happy path", func(t *testing.T) {
	// 	f.Password = "P@ssw0rd"
	// 	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		respondUnprovision(t, w)
	// 	})
	// 	lps := setupWithWsmanClient(f, handler)
	// 	err := lps.Deactivate()
	// 	assert.Equal(t, nil, err)
	// })
	t.Run("returns UnableToDeactivate with no password", func(t *testing.T) {
		f.Password = ""
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondServerError(w)
		})
		lps := setupWithWsmanClient(f, handler)
		err := lps.Deactivate()
		assert.Equal(t, utils.MissingOrIncorrectPassword, err)
	})

	t.Run("returns UnableToDeactivate on SetupAndConfigurationService.Unprovision server error", func(t *testing.T) {
		f.Password = "P@ssw0rd"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondServerError(w)
		})
		lps := setupWithWsmanClient(f, handler)
		err := lps.Deactivate()
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
	t.Run("returns UnableToDeactivate on SetupAndConfigurationService.Unprovision xml error", func(t *testing.T) {
		f.Password = "P@ssw0rd"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondBadXML(t, w)
		})
		lps := setupWithWsmanClient(f, handler)
		err := lps.Deactivate()
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
	// t.Run("returns DeactivationFailed when unprovision ReturnStatus is not success (0)", func(t *testing.T) {
	// 	f.Password = "P@ssw0rd"
	// 	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		mockUnprovisionResponse.ReturnValue = 1
	// 		respondUnprovision(t, w)
	// 		mockUnprovisionResponse.ReturnValue = 0
	// 	})
	// 	lps := setupWithWsmanClient(f, handler)
	// 	err := lps.Deactivate()
	// 	assert.Equal(t, utils.DeactivationFailed, err)
	// })
}
