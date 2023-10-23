package local

import (
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDisplayVersion(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandVersion

	t.Run("should return Success", func(t *testing.T) {
		lps := setupService(f)
		rc := lps.DisplayVersion()
		assert.Equal(t, utils.Success, rc)
	})

	t.Run("should return Success with json output", func(t *testing.T) {
		f.JsonOutput = true
		lps := setupService(f)
		rc := lps.DisplayVersion()
		assert.Equal(t, utils.Success, rc)
		f.JsonOutput = false
	})

}
