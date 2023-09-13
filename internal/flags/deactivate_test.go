package flags

import (
	"rpc/pkg/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleDeactivateCommandNoFlags(t *testing.T) {
	args := []string{"./rpc", "deactivate"}
	flags := NewFlags(args)
	flags.amtCommand.PTHI = MockPTHICommands{}
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.IncorrectCommandLineParameters)
}
func TestHandleDeactivateInvalidFlag(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-x"}

	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.IncorrectCommandLineParameters)
}

func TestHandleDeactivateCommandNoPasswordPrompt(t *testing.T) {
	password := "password"
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost"}
	defer userInput(t, password)()
	flags := NewFlags(args)
	success := flags.ParseFlags()
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, utils.CommandDeactivate, flags.Command)
	assert.Equal(t, password, flags.Password)
}
func TestHandleDeactivateCommandNoPasswordPromptEmpy(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost"}
	defer userInput(t, "")()
	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.MissingOrIncorrectPassword)
}
func TestHandleDeactivateCommandNoURL(t *testing.T) {
	args := []string{"./rpc", "deactivate", "--password", "password"}

	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.MissingOrIncorrectURL)
}
func TestHandleDeactivateCommand(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password"}
	expected := utils.CommandDeactivate
	flags := NewFlags(args)
	success := flags.ParseFlags()
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, expected, flags.Command)
}

func TestHandleDeactivateCommandWithURLAndLocal(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password", "-local"}
	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.InvalidParameterCombination)
	assert.Equal(t, "wss://localhost", flags.URL)
}
func TestHandleDeactivateCommandWithForce(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password", "-f"}
	expected := utils.CommandDeactivate
	flags := NewFlags(args)
	success := flags.ParseFlags()
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, true, flags.Force)
	assert.Equal(t, expected, flags.Command)
}

func TestHandleLocalDeactivationWithPassword(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-local", "--password", "p@ssword"}
	flags := NewFlags(args)
	errCode := flags.ParseFlags()
	assert.Equal(t, errCode, utils.Success)
}

func TestHandleLocalDeactivationWithoutPassword(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-local"}
	flags := NewFlags(args)
	rc := flags.ParseFlags()
	assert.Equal(t, rc, utils.Success)
}

func TestParseFlagsDeactivate(t *testing.T) {
	args := []string{"./rpc", "deactivate"}
	flags := NewFlags(args)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, utils.CommandDeactivate, flags.Command)
}
