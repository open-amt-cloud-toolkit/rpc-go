package flags

import (
	"rpc/pkg/utils"
)

type OpStateFlags struct {
	Disable bool
	Enable  bool
}

func (f *Flags) handleAmtOpStateCommand() utils.ReturnCode {
	f.Local = true
	f.amtOpStateCommand.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.amtOpStateCommand.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.amtOpStateCommand.BoolVar(&f.OpStateFlags.Disable, "disable", false, "Disable AMT")
	f.amtOpStateCommand.BoolVar(&f.OpStateFlags.Enable, "enable", false, "Enable AMT")
	if err := f.amtOpStateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}
	return utils.Success
}
