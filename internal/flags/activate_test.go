package flags

import (
	"os"
	"rpc/pkg/utils"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHandleActivateCommandNoFlags(t *testing.T) {
	args := []string{"./rpc", "activate"}
	flags := NewFlags(args)
	success := flags.ParseFlags()
	assert.Equal(t, success, utils.IncorrectCommandLineParameters)
}
func TestHandleActivateCommand(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName", "-password", "Password"}
	flags := NewFlags(args)
	var AMTTimeoutDuration time.Duration = 120000000000
	rc := flags.ParseFlags()
	assert.Equal(t, utils.Success, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, utils.CommandActivate, flags.Command)
	assert.Equal(t, "Password", flags.Password)
	assert.Equal(t, "localhost", flags.LMSAddress)
	assert.Equal(t, "16992", flags.LMSPort)
	// 2m default
	assert.Equal(t, AMTTimeoutDuration, flags.AMTTimeoutDuration)
	assert.Equal(t, "", flags.FriendlyName)
}

func TestHandleActivateCommandWithTimeOut(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName", "-password", "Password", "-t", "2s"}
	flags := NewFlags(args)
	var AMTTimeoutDuration time.Duration = 2000000000
	rc := flags.ParseFlags()
	assert.Equal(t, utils.Success, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, utils.CommandActivate, flags.Command)
	assert.Equal(t, "Password", flags.Password)
	assert.Equal(t, "localhost", flags.LMSAddress)
	assert.Equal(t, "16992", flags.LMSPort)
	assert.Equal(t, AMTTimeoutDuration, flags.AMTTimeoutDuration)
}
func TestHandleActivateCommandWithLMS(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName", "-lmsaddress", "1.1.1.1", "-lmsport", "99"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.Success, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, utils.CommandActivate, flags.Command)
	assert.Equal(t, "1.1.1.1", flags.LMSAddress)
	assert.Equal(t, "99", flags.LMSPort)
}
func TestHandleActivateCommandWithFriendlyName(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName", "-name", "friendlyName"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.Success, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, utils.CommandActivate, flags.Command)
	assert.Equal(t, "friendlyName", flags.FriendlyName)
}
func TestHandleActivateCommandWithENV(t *testing.T) {

	if err := os.Setenv("DNS_SUFFIX", "envdnssuffix.com"); err != nil {
		t.Error(err)
	}
	if err := os.Setenv("HOSTNAME", "envhostname"); err != nil {
		t.Error(err)
	}
	if err := os.Setenv("PROFILE", "envprofile"); err != nil {
		t.Error(err)
	}
	if err := os.Setenv("AMT_PASSWORD", "envpassword"); err != nil {
		t.Error(err)
	}

	args := []string{"./rpc", "activate", "-u", "wss://localhost"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.Success, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "envprofile", flags.Profile)
	assert.Equal(t, utils.CommandActivate, flags.Command)
	assert.Equal(t, "envpassword", flags.Password)
	os.Clearenv()
}

func TestActivateOverrideUUID(t *testing.T) {
	if err := os.Setenv("PROFILE", "envprofile"); err != nil {
		t.Error(err)
	}

	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-uuid", "4c2e8db8-1c7a-00ea-279c-d17395b1f584"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.Success, rc)
	assert.Equal(t, flags.UUID, "4c2e8db8-1c7a-00ea-279c-d17395b1f584")
	os.Clearenv()
}

func TestActivateInvalidUUID(t *testing.T) {
	if err := os.Setenv("PROFILE", "envprofile"); err != nil {
		t.Error(err)
	}

	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-uuid", "12345"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.InvalidUUID, rc)
	os.Clearenv()
}

func TestActivateIncorrectParameterCombinationLocalAndUUID(t *testing.T) {
	if err := os.Setenv("AMT_PASSWORD", "envpassword"); err != nil {
		t.Error(err)
	}

	args := []string{"./rpc", "activate", "-ccm", "-local", "-uuid", "12345678-1234-1234-1234-123456789012"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.InvalidParameterCombination, rc)
	os.Clearenv()
}

func TestHandleActivateCommandIncorrectCommandLineParameters(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-x"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.IncorrectCommandLineParameters, rc)
}

func TestHandleActivateCommandNoProfile(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.MissingOrIncorrectProfile, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandNoProxy(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-p"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.MissingProxyAddressAndPort, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandNoHostname(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-h"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.MissingHostname, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandNoDNSSuffix(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-d"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.MissingDNSSuffix, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandMissingProfile(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.MissingOrIncorrectProfile, rc)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandBothURLandLocal(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-local"}
	flags := NewFlags(args)
	success := flags.ParseFlags()
	assert.EqualValues(t, success, utils.InvalidParameterCombination)
}

func TestHandleActivateCommandNoURL(t *testing.T) {
	args := []string{"./rpc", "activate", "-profile", "profileName"}

	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, utils.MissingOrIncorrectURL, rc)
	assert.Equal(t, "profileName", flags.Profile)
}

func TestHandleActivateCommandLocal(t *testing.T) {

	tests := map[string]struct {
		cmdLine    string
		wantResult utils.ReturnCode
	}{
		"should fail with both URL and local": {
			cmdLine:    "./rpc activate -local -u wss://localhost",
			wantResult: utils.InvalidParameterCombination,
		},
		"should fail without acm or ccm specified": {
			cmdLine:    "./rpc activate -local",
			wantResult: utils.InvalidParameterCombination,
		},
		"should fail if both acm and ccm specified": {
			cmdLine:    "./rpc activate -local -acm -ccm",
			wantResult: utils.InvalidParameterCombination,
		},
		"should fail if ccm and missing password": {
			cmdLine:    "./rpc activate -local -ccm",
			wantResult: utils.MissingOrIncorrectPassword,
		},
		"should fail if acm and local config file error": {
			cmdLine:    "./rpc activate -local -acm -config ./nofilehere.txt",
			wantResult: utils.FailedReadingConfiguration,
		},
		"should fail if acm and ACM Settings not specified": {
			cmdLine:    "./rpc activate -local -acm",
			wantResult: utils.IncorrectCommandLineParameters,
		},
		"should pass if acm with example config file": {
			cmdLine:    "./rpc activate -local -acm -config ../../config.yaml",
			wantResult: utils.Success,
		},
		"should pass wif acm and ACM Settings specified": {
			cmdLine: "./rpc activate -local -acm " +
				" -amtPassword " + trickyPassword +
				` -provisioningCert MIIW/gIBAzCCFroGCSqGSIb3DQEHAaCCFqsEghanMIIWozCCBgwGCSqGSIb3DQEHAaCCBf0EggX5MIIF9TCCBfEGCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvc` +
				" -provisioningCertPwd " + trickyPassword,
			wantResult: utils.Success,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			flags := NewFlags(args)
			gotResult := flags.ParseFlags()
			assert.Equal(t, tc.wantResult, gotResult)
			assert.Equal(t, utils.CommandActivate, flags.Command)
		})
	}

}
