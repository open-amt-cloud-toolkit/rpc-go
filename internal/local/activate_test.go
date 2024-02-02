package local

import (
	"crypto/x509"
	"errors"
	amt2 "rpc/internal/amt"
	"rpc/internal/certtest"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

var sortaSingletonCerts *certtest.TestCerts = nil

func getTestCerts() *certtest.TestCerts {
	if sortaSingletonCerts == nil {
		sortaSingletonCerts = certtest.New("P@ssw0rd")
	}
	return sortaSingletonCerts
}

func TestActivation(t *testing.T) {
	lps := setupService(&flags.Flags{})
	lps.flags.Command = utils.CommandActivate
	lps.flags.LocalConfig.Password = "P@ssw0rd"

	t.Run("returns AMTConnectionFailed when GetControlMode fails", func(t *testing.T) {
		mockControlModeErr = errors.New("yep it failed")
		rc := lps.Activate()
		assert.Equal(t, utils.AMTConnectionFailed, rc)
		mockControlModeErr = nil
	})

	t.Run("returns UnableToActivate when already activated", func(t *testing.T) {
		mockControlMode = 1
		rc := lps.Activate()
		assert.Equal(t, utils.UnableToActivate, rc)
		mockControlMode = 0
	})

	t.Run("returns AMTConnectionFailed when GetLocalSystemAccount fails", func(t *testing.T) {
		mockLocalSystemAccountErr = errors.New("yep it failed")
		rc := lps.Activate()
		assert.Equal(t, utils.AMTConnectionFailed, rc)
		mockLocalSystemAccountErr = nil
	})

	t.Run("returns ActivationFailed when UseACM and responses are not mocked", func(t *testing.T) {
		lps.flags.UseACM = true
		rc := lps.Activate()
		assert.Equal(t, utils.ActivationFailed, rc)
		lps.flags.UseACM = false
	})

	t.Run("returns ActivationFailed when UseCCM and responses are not mocked", func(t *testing.T) {
		lps.flags.UseCCM = true
		rc := lps.Activate()
		assert.Equal(t, utils.ActivationFailed, rc)
		lps.flags.UseCCM = false
	})
}

func TestActivateCCM(t *testing.T) {
	f := &flags.Flags{}
	t.Run("returns ActivationFailed on GeneralSettings.Get() server error", func(t *testing.T) {
		lps := setupService(f)
		rc := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, rc)
	})

	t.Run("returns ActivationFailed on GeneralSettings.Get() xml.unmarshal error", func(t *testing.T) {
		lps := setupService(f)
		rc := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, rc)
	})

	t.Run("returns ActivationFailed on HostBasedSetupService.Setup server error", func(t *testing.T) {
		lps := setupService(f)
		rc := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, rc)
	})

	t.Run("returns ActivationFailed on HostBasedSetupService.Setup xml.unmarshal error", func(t *testing.T) {
		lps := setupService(f)
		rc := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, rc)
	})

	t.Run("returns ActivationFailed on HostBasedSetupService.Setup ReturnValue is not success (0)", func(t *testing.T) {
		lps := setupService(f)
		rc := lps.ActivateCCM()
		assert.Equal(t, utils.ActivationFailed, rc)
	})

	t.Run("returns Success on happy path", func(t *testing.T) {
		lps := setupService(f)
		rc := lps.ActivateCCM()
		assert.Equal(t, nil, rc)
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
	lps := setupService(f)
	rc := lps.ActivateACM()
	assert.Equal(t, nil, rc)
}

func TestInjectCertsErrors(t *testing.T) {
	f := &flags.Flags{}
	testCerts := getTestCerts()

	certs := []string{testCerts.LeafPem, testCerts.InterPem, testCerts.CaPem}

	t.Run("returns error on server error response", func(t *testing.T) {
		lps := setupService(f)
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
