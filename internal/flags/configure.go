package flags

import (
	"rpc/pkg/utils"
)

func (f *Flags) handleConfigureCommand() int {
	if err := f.amtConfigureCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}
	// runs locally
	f.Local = true
	return utils.Success
}
