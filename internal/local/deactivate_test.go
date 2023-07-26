package local

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
)

func mockUnprovisionResponse(returnValue string) string {
	return xmlBodyStart +
		"<g:Unprovision_OUTPUT><g:ReturnValue>" + returnValue + "</g:ReturnValue></g:Unprovision_OUTPUT>" +
		xmlBodyEnd
}

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
}

func TestDeactivateCCM(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	mockControlMode = 1

	t.Run("should return Success for CCM happy path", func(t *testing.T) {
		lps := setupService(f)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.Success, resultCode)
	})
	t.Run("should return DeactivationFailed for CCM AMT unprovision err", func(t *testing.T) {
		mockUnprovisionErr = errors.New("test error")
		lps := setupService(f)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, resultCode)
		mockUnprovisionErr = nil
	})
	t.Run("should return DeactivationFailed for CCM AMT unprovision non zero status", func(t *testing.T) {
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

	t.Run("should return Success for ACM happy path", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			_, writeErr := w.Write([]byte(mockUnprovisionResponse("0")))
			assert.Nil(t, writeErr)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.Success, resultCode)
	})

	t.Run("should return UnableToDeactivate for client.Post error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.UnableToDeactivate, resultCode)
	})
	t.Run("should return DeactivationFailed on non-zero ReturnValue", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			_, writeErr := w.Write([]byte(mockUnprovisionResponse("1")))
			assert.Nil(t, writeErr)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Deactivate()
		assert.Equal(t, utils.DeactivationFailed, resultCode)
	})
}
