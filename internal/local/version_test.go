package local

import (
	"github.com/stretchr/testify/assert"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
)

func TestDisplayVersion(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandVersion

	t.Run("should return Success", func(t *testing.T) {
		lps := setupService(f)
		resultCode := lps.DisplayVersion()
		assert.Equal(t, utils.Success, resultCode)
	})

	t.Run("should return Success with json output", func(t *testing.T) {
		f.JsonOutput = true
		lps := setupService(f)
		resultCode := lps.DisplayVersion()
		assert.Equal(t, utils.Success, resultCode)
		f.JsonOutput = false
	})

}
