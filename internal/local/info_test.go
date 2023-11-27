package local

import (
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	"github.com/stretchr/testify/assert"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
)

func TestDisplayAMTInfo(t *testing.T) {
	//f := &flags.Flags{}
	defaultFlags := flags.AmtInfoFlags{
		Ver:      true,
		Bld:      true,
		Sku:      true,
		UUID:     true,
		Mode:     true,
		DNS:      true,
		Ras:      true,
		Lan:      true,
		Hostname: true,
		OpState:  true,
	}

	t.Run("returns Success on happy path", func(t *testing.T) {
		f := &flags.Flags{}
		f.AmtInfo = defaultFlags
		lps := setupService(f)
		rc := lps.DisplayAMTInfo()
		assert.Equal(t, utils.Success, rc)
	})

	t.Run("returns Success with json output", func(t *testing.T) {
		f := &flags.Flags{}
		f.AmtInfo = defaultFlags
		f.JsonOutput = true
		lps := setupService(f)
		resultCode := lps.DisplayAMTInfo()
		assert.Equal(t, utils.Success, resultCode)
	})

	t.Run("returns Success with certs", func(t *testing.T) {
		f := &flags.Flags{}
		f.AmtInfo.Cert = true
		f.AmtInfo.UserCert = true
		f.Password = "testPassword"
		mockCertHashes = mockCertHashesDefault
		pullEnvelope := publickey.PullResponseEnvelope{}
		pullEnvelope.Body.PullResponse.Items = []publickey.PublicKeyCertificate{
			mpsCert,
			clientCert,
			caCert,
		}
		rfa := ResponseFuncArray{
			respondMsgFunc(t, common.EnumerationResponse{}),
			respondMsgFunc(t, pullEnvelope),
		}
		lps := setupWsmanResponses(t, f, rfa)
		resultCode := lps.DisplayAMTInfo()
		assert.Equal(t, utils.Success, resultCode)
	})

	t.Run("returns Success but logs errors on error conditions", func(t *testing.T) {
		mockUUIDErr = mockStandardErr
		mockVersionDataErr = mockStandardErr
		mockControlModeErr = mockStandardErr
		mockDNSSuffixErr = mockStandardErr
		mockOSDNSSuffixErr = mockStandardErr
		mockRemoteAcessConnectionStatusErr = mockStandardErr
		mockLANInterfaceSettingsErr = mockStandardErr
		mockCertHashesErr = mockStandardErr

		f := &flags.Flags{}
		f.AmtInfo = defaultFlags
		f.JsonOutput = true

		lps := setupService(f)
		rc := lps.DisplayAMTInfo()
		assert.Equal(t, utils.Success, rc)
		f.JsonOutput = false

		mockUUIDErr = nil
		mockVersionDataErr = nil
		mockControlModeErr = nil
		mockDNSSuffixErr = nil
		mockOSDNSSuffixErr = nil
		mockRemoteAcessConnectionStatusErr = nil
		mockLANInterfaceSettingsErr = nil
		mockCertHashesErr = nil
	})

	t.Run("resets UserCert on GetControlMode failure", func(t *testing.T) {
		f := &flags.Flags{}
		f.AmtInfo.UserCert = true
		mockControlModeErr = mockStandardErr
		rfa := ResponseFuncArray{}
		lps := setupWsmanResponses(t, f, rfa)
		resultCode := lps.DisplayAMTInfo()
		assert.Equal(t, utils.Success, resultCode)
		assert.False(t, f.AmtInfo.UserCert)
		mockControlModeErr = nil
	})
	t.Run("resets UserCert when control mode is preprovisioning", func(t *testing.T) {
		f := &flags.Flags{}
		f.AmtInfo.UserCert = true
		orig := mockControlMode
		mockControlMode = 0
		rfa := ResponseFuncArray{}
		lps := setupWsmanResponses(t, f, rfa)
		resultCode := lps.DisplayAMTInfo()
		assert.Equal(t, utils.Success, resultCode)
		assert.False(t, f.AmtInfo.UserCert)
		mockControlMode = orig
	})
	t.Run("returns MissingOrIncorrectPassword on no password input from user", func(t *testing.T) {
		f := &flags.Flags{}
		f.AmtInfo.UserCert = true
		orig := mockControlMode
		mockControlMode = 2
		rfa := ResponseFuncArray{}
		lps := setupWsmanResponses(t, f, rfa)
		resultCode := lps.DisplayAMTInfo()
		assert.Equal(t, utils.MissingOrIncorrectPassword, resultCode)
		assert.True(t, f.AmtInfo.UserCert)
		mockControlMode = orig
	})
}

func TestDecodeAMT(t *testing.T) {
	testCases := []struct {
		version string
		SKU     string
		want    string
	}{
		{"200", "0", "Invalid AMT version format"},
		{"ab.c", "0", "Invalid AMT version"},
		{"2.0.0", "0", "AMT + ASF + iQST"},
		{"2.1.0", "1", "ASF + iQST"},
		{"2.2.0", "2", "iQST"},
		{"1.1.0", "3", "Unknown"},
		{"3.0.0", "008", "Invalid SKU"},
		{"3.0.0", "8", "AMT"},
		{"4.1.0", "2", "iQST "},
		{"4.0.0", "4", "ASF "},
		{"5.0.0", "288", "TPM Home IT "},
		{"5.0.0", "1088", "WOX "},
		{"5.0.0", "38", "iQST ASF TPM "},
		{"5.0.0", "4", "ASF "},
		{"6.0.0", "2", "iQST "},
		{"7.0.0", "36864", "L3 Mgt Upgrade"},
		{"8.0.0", "24584", "AMT Pro AT-p Corporate "},
		{"10.0.0", "8", "AMT Pro "},
		{"11.0.0", "16392", "AMT Pro Corporate "},
		{"15.0.42", "16392", "AMT Pro Corporate "},
		{"16.1.25", "16400", "Intel Standard Manageability Corporate "},
	}

	for _, tc := range testCases {
		got := DecodeAMT(tc.version, tc.SKU)
		if got != tc.want {
			t.Errorf("DecodeAMT(%q, %q) = %v; want %v", tc.version, tc.SKU, got, tc.want)
		}
	}
}
