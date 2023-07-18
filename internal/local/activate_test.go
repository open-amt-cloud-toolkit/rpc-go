package local

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
)

func mockGetGeneralSettingsResponse() string {
	return xmlBodyStart +
		"<g:AMT_GeneralSettings><g:HostName>test.hostname.org</g:HostName></g:AMT_GeneralSettings>" +
		xmlBodyEnd
}

func mockHostBasedSetupResponse(returnValue string) string {
	return xmlBodyStart +
		"<g:Setup_OUTPUT><g:ReturnValue>" + returnValue + "</g:ReturnValue></g:Setup_OUTPUT>" +
		xmlBodyEnd
}

func TestActivation(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandActivate
	f.LocalConfig.Password = "P@ssw0rd"

	t.Run("returns AMTConnectionFailed when GetControlMode fails", func(t *testing.T) {
		lps := setupService(f)
		mockControlModeErr = errors.New("yep it failew")
		resultCode := lps.Activate()
		assert.Equal(t, utils.AMTConnectionFailed, resultCode)
		mockControlModeErr = nil
	})

	t.Run("returns UnableToActivate when already activated", func(t *testing.T) {
		lps := setupService(f)
		mockControlMode = 1
		resultCode := lps.Activate()
		assert.Equal(t, utils.UnableToActivate, resultCode)
		mockControlMode = 0
	})

	t.Run("returns AMTConnectionFailed when GetLocalSystemAccount fails", func(t *testing.T) {
		lps := setupService(f)
		mockLocalSystemAccountErr = errors.New("yep it failew")
		resultCode := lps.Activate()
		assert.Equal(t, utils.AMTConnectionFailed, resultCode)
		mockLocalSystemAccountErr = nil
	})

	t.Run("returns AMTFailed when CCM activate responses are not mocked", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
		})
		f.UseCCM = false
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Activate()
		assert.Equal(t, utils.ActivationFailed, resultCode)
		assert.Equal(t, true, f.UseCCM)
	})

	t.Run("returns Success on the happy path", func(t *testing.T) {
		f := &flags.Flags{}
		count := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			var writeErr error
			switch count {
			case 0:
				_, writeErr = w.Write([]byte(mockGetGeneralSettingsResponse()))
				break
			case 1:
				_, writeErr = w.Write([]byte(mockHostBasedSetupResponse("0")))
				break
			}
			assert.Nil(t, writeErr)
			count++
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Activate()
		assert.Equal(t, utils.Success, resultCode)
	})
}

func TestActivateACM(t *testing.T) {
	f := &flags.Flags{}
	t.Run("returns ActivationFailed when GetControlMode fails", func(t *testing.T) {
		lps := setupService(f)
		resultCode := lps.ActivateACM()
		assert.Equal(t, utils.ActivationFailed, resultCode)
	})

	t.Run("returns ActivationFailed if HostBasedSetup returns an error", func(t *testing.T) {
		f := &flags.Flags{}
		count := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			var writeErr error
			switch count {
			case 0:
				_, writeErr = w.Write([]byte(mockGetGeneralSettingsResponse()))
				break
			case 1:
				w.WriteHeader(http.StatusInternalServerError)
				break
			}
			assert.Nil(t, writeErr)
			count++
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.Activate()
		assert.Equal(t, utils.ActivationFailed, resultCode)
	})

}

func TestActivateHostBasedSetup(t *testing.T) {
	t.Run("returns AMTConnectionFailed when client.Post fails", func(t *testing.T) {
		f := &flags.Flags{}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode, err := lps.HostBasedSetup("faketestrealm", "faketestpassword")
		assert.NotNil(t, err)
		assert.Equal(t, utils.AMTConnectionFailed, resultCode)
	})
	t.Run("returns ActivationFailed when hostbasedsetup.Response is bad", func(t *testing.T) {
		f := &flags.Flags{}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			_, err := w.Write([]byte(xmlBodyStart))
			assert.Nil(t, err)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode, err := lps.HostBasedSetup("faketestrealm", "faketestpassword")
		assert.NotNil(t, err)
		assert.Equal(t, utils.ActivationFailed, resultCode)
	})
	t.Run("returns ActivationFailed when Setup_OUTPUT.ReturnValue is bad", func(t *testing.T) {
		f := &flags.Flags{}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			_, err := w.Write([]byte(mockHostBasedSetupResponse("1")))
			assert.Nil(t, err)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode, err := lps.HostBasedSetup("faketestrealm", "faketestpassword")
		assert.NotNil(t, err)
		assert.Equal(t, utils.ActivationFailed, resultCode)
	})
	t.Run("success on happy path", func(t *testing.T) {
		f := &flags.Flags{}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			_, err := w.Write([]byte(mockHostBasedSetupResponse("0")))
			assert.Nil(t, err)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode, err := lps.HostBasedSetup("faketestrealm", "faketestpassword")
		assert.Nil(t, err)
		assert.Equal(t, utils.Success, resultCode)
	})
}
