package flags

import (
	"github.com/stretchr/testify/assert"
	"rpc/pkg/utils"
	"testing"
)

func TestHandleVersionCommand(t *testing.T) {
	f := NewFlags([]string{
		"rpc",
		"version",
	})

	result := f.handleVersionCommand()
	assert.Equal(t, utils.Success, result)
	assert.Equal(t, true, f.Local)
}
