package local

import (
	"crypto/x509"
	"errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	amt2 "rpc/internal/amt"
	"rpc/internal/certtest"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
)

var sortaSingletonCerts *certtest.TestCerts = nil

func getTestCerts() *certtest.TestCerts {
	if sortaSingletonCerts == nil {
		sortaSingletonCerts = certtest.New("P@ssw0rd")
	}
	return sortaSingletonCerts
}

func TestActivation(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondServerError(w)
	})
	lps := setupWithTestServer(&flags.Flags{}, handler)
	lps.flags.Command = utils.CommandActivate
	lps.flags.LocalConfig.Password = "P@ssw0rd"

	t.Run("returns AMTConnectionFailed when GetControlMode fails", func(t *testing.T) {
		mockControlModeErr = errors.New("yep it failed")
		resultCode := lps.Activate()
		assert.Equal(t, utils.AMTConnectionFailed, resultCode)
		mockControlModeErr = nil
	})

	t.Run("returns UnableToActivate when already activated", func(t *testing.T) {
		mockControlMode = 1
		resultCode := lps.Activate()
		assert.Equal(t, utils.UnableToActivate, resultCode)
		mockControlMode = 0
	})

	t.Run("returns AMTConnectionFailed when GetLocalSystemAccount fails", func(t *testing.T) {
		mockLocalSystemAccountErr = errors.New("yep it failed")
		resultCode := lps.Activate()
		assert.Equal(t, utils.AMTConnectionFailed, resultCode)
		mockLocalSystemAccountErr = nil
	})

	t.Run("returns ActivationFailed when UseACM and responses are not mocked", func(t *testing.T) {
		lps.flags.UseACM = true
		resultCode := lps.Activate()
		assert.Equal(t, utils.ActivationFailed, resultCode)
		lps.flags.UseACM = false
	})

	t.Run("returns ActivationFailed when UseCCM and responses are not mocked", func(t *testing.T) {
		lps.flags.UseCCM = true
		resultCode := lps.Activate()
		assert.Equal(t, utils.ActivationFailed, resultCode)
		lps.flags.UseCCM = false
	})
}

func TestActivateCCM(t *testing.T) {
	f := &flags.Flags{}

	t.Run("returns ActivationFailed on GeneralSettings.Get() server error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondServerError(w)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, resultCode)
	})

	t.Run("returns ActivationFailed on GeneralSettings.Get() xml.unmarshal error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondBadXML(t, w)
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, resultCode)
	})

	t.Run("returns ActivationFailed on HostBasedSetupService.Setup server error", func(t *testing.T) {
		calls := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				respondGeneralSettings(t, w)
			} else if calls == 2 {
				respondServerError(w)
			}
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, resultCode)
	})

	t.Run("returns ActivationFailed on HostBasedSetupService.Setup xml.unmarshal error", func(t *testing.T) {
		calls := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				respondGeneralSettings(t, w)
			} else if calls == 2 {
				respondBadXML(t, w)
			}
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, resultCode)
	})

	t.Run("returns ActivationFailed on HostBasedSetupService.Setup ReturnValue is not success (0)", func(t *testing.T) {
		calls := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				respondGeneralSettings(t, w)
			} else if calls == 2 {
				mockHostBasedSetupResponse.Body.Setup_OUTPUT.ReturnValue = 1
				respondHostBasedSetup(t, w)
				mockHostBasedSetupResponse.Body.Setup_OUTPUT.ReturnValue = 0
			}
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, resultCode)
	})

	t.Run("returns Success on happy path", func(t *testing.T) {
		calls := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				respondGeneralSettings(t, w)
			} else if calls == 2 {
				respondHostBasedSetup(t, w)
			}
		})
		lps := setupWithWsmanClient(f, handler)
		resultCode := lps.ActivateCCM()
		assert.Equal(t, utils.Success, resultCode)
	})
}

func TestGetHostBasedSetupService(t *testing.T) {
	f := &flags.Flags{}

	t.Run("returns error on server error response", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondServerError(w)
		})
		lps := setupWithWsmanClient(f, handler)
		_, err := lps.GetHostBasedSetupService()
		assert.NotNil(t, err)
	})

	t.Run("returns error on xml.unmarshal error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondBadXML(t, w)
		})
		lps := setupWithWsmanClient(f, handler)
		_, err := lps.GetHostBasedSetupService()
		assert.NotNil(t, err)
	})

	t.Run("returns valid response on happy path", func(t *testing.T) {
		expected := "test_name"
		mockHostBasedSetupResponse.Body.IPS_HostBasedSetupService.SystemName = expected
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondHostBasedSetup(t, w)
		})
		lps := setupWithWsmanClient(f, handler)
		rsp, err := lps.GetHostBasedSetupService()
		assert.Nil(t, err)
		assert.Equal(t, expected, rsp.Body.IPS_HostBasedSetupService.SystemName)
		mockHostBasedSetupResponse.Body.IPS_HostBasedSetupService.SystemName = ""
	})
}

func TestGetGeneralSettings(t *testing.T) {
	f := &flags.Flags{}

	t.Run("returns error on server error response", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondServerError(w)
		})
		lps := setupWithWsmanClient(f, handler)
		_, err := lps.GetGeneralSettings()
		assert.NotNil(t, err)
	})

	t.Run("returns error on xml.unmarshal error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondBadXML(t, w)
		})
		lps := setupWithWsmanClient(f, handler)
		_, err := lps.GetGeneralSettings()
		assert.NotNil(t, err)
	})

	t.Run("returns valid response on happy path", func(t *testing.T) {
		expected := "test_name"
		mockGenerlSettingsResponse.Body.AMTGeneralSettings.HostName = expected
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondGeneralSettings(t, w)
		})
		lps := setupWithWsmanClient(f, handler)
		rsp, err := lps.GetGeneralSettings()
		assert.Nil(t, err)
		assert.Equal(t, expected, rsp.Body.AMTGeneralSettings.HostName)
		mockGenerlSettingsResponse.Body.AMTGeneralSettings.HostName = ""
	})
}

func TestActivateACM(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.ACMSettings.AMTPassword = "P@ssw0rd"
	testCerts := getTestCerts()
	f.LocalConfig.ACMSettings.ProvisioningCert = testCerts.Pfxb64
	f.LocalConfig.ACMSettings.ProvisioningCertPwd = testCerts.PfxPassword

	mockCertHashes = []amt2.CertHashEntry{
		{
			Hash:      testCerts.CaFingerprint,
			Name:      "",
			Algorithm: "",
			IsActive:  true,
			IsDefault: true,
		},
	}
	calls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		var err error
		calls++
		if calls == 1 {
			respondGeneralSettings(t, w)
		} else {
			respondHostBasedSetup(t, w)
		}
		assert.Nil(t, err)
	})
	lps := setupWithWsmanClient(f, handler)
	resultCode := lps.ActivateACM()
	assert.Equal(t, utils.Success, resultCode)
}

func TestInjectCertsErrors(t *testing.T) {
	f := &flags.Flags{}
	testCerts := getTestCerts()

	certs := []string{testCerts.LeafPem, testCerts.InterPem, testCerts.CaPem}

	t.Run("returns error on server error response", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondServerError(w)
		})
		lps := setupWithWsmanClient(f, handler)
		err := lps.injectCertificate(certs)
		assert.NotNil(t, err)
	})

	t.Run("returns error on xml.unmarshal error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondBadXML(t, w)
		})
		lps := setupWithWsmanClient(f, handler)
		err := lps.injectCertificate(certs)
		assert.NotNil(t, err)
	})
}

func TestDumpPfx(t *testing.T) {
	certsAndKeys := CertsAndKeys{}
	_, _, err := dumpPfx(certsAndKeys)
	assert.NotNil(t, err)
	certsAndKeys.certs = []*x509.Certificate{{}}
	_, _, err = dumpPfx(certsAndKeys)
	assert.NotNil(t, err)
}
