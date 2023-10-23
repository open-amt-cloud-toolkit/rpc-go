package flags

import (
	"fmt"
	"rpc/pkg/utils"
)

func (f *Flags) handleDeactivateCommand() utils.ReturnCode {
	f.amtDeactivateCommand.BoolVar(&f.Local, "local", false, "Execute command to AMT directly without cloud interaction")
	if len(f.commandLineArgs) == 2 {
		f.amtDeactivateCommand.PrintDefaults()
		return utils.IncorrectCommandLineParameters
	}
	if err := f.amtDeactivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}
	if f.Local && f.URL != "" {
		fmt.Println("provide either a 'url' or a 'local', but not both")
		return utils.InvalidParameterCombination
	}
	if !f.Local {
		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtDeactivateCommand.Usage()
			return utils.MissingOrIncorrectURL
		}
		if f.Password == "" {
			if _, rc := f.ReadPasswordFromUser(); rc != 0 {
				return utils.MissingOrIncorrectPassword
			}
		}
	}
	return utils.Success
}
