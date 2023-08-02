package flags

import (
	"rpc/pkg/utils"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleConfigureCommand(t *testing.T) {
	cmdLine := "rpc configure --config ../../config-wifi.yaml "
	args := strings.Fields(cmdLine)
	flags := NewFlags(args)
	gotResult := flags.ParseFlags()
	assert.Equal(t, flags.Local, true)
	assert.Equal(t, utils.Success, gotResult)
	assert.Equal(t, utils.CommandConfigure, flags.Command)
}
