package flags

import (
	"rpc/pkg/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleConfigureCommand(t *testing.T) {
	f := NewFlags([]string{
		"rpc",
		"configure",
	})

	result := f.handleConfigureCommand()
	assert.Equal(t, utils.Success, result)
	assert.Equal(t, true, f.Local)
}
