package local

import (
	"github.com/stretchr/testify/assert"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
)

func TestDisplayAMTInfo(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandVersion
	f.AmtInfo.Ver = true
	f.AmtInfo.Bld = true
	f.AmtInfo.Sku = true
	f.AmtInfo.UUID = true
	f.AmtInfo.Mode = true
	f.AmtInfo.DNS = true
	f.AmtInfo.Cert = true
	f.AmtInfo.Ras = true
	f.AmtInfo.Lan = true
	f.AmtInfo.Hostname = true

	t.Run("should return Success", func(t *testing.T) {
		lps := setupService(f)
		resultCode := lps.DisplayAMTInfo()
		assert.Equal(t, utils.Success, resultCode)
	})

	t.Run("should return Success with json output", func(t *testing.T) {
		f.JsonOutput = true
		lps := setupService(f)
		resultCode := lps.DisplayAMTInfo()
		assert.Equal(t, utils.Success, resultCode)
		f.JsonOutput = false
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
		got := decodeAMT(tc.version, tc.SKU)
		if got != tc.want {
			t.Errorf("decodeAMT(%q, %q) = %v; want %v", tc.version, tc.SKU, got, tc.want)
		}
	}
}
