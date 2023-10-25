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
	f.amtOpStateCommand.BoolVar(&f.OpStateFlags.Disable, "disable", false, "Disable AMT")
	f.amtOpStateCommand.BoolVar(&f.OpStateFlags.Enable, "enable", false, "Enable AMT")
	f.amtOpStateCommand.StringVar(&f.DNS, "d", f.lookupEnvOrString("DNS_SUFFIX", ""), "dns suffix override")
	//if len(f.commandLineArgs) == 2 {
	//	f.amtOpStateCommand.PrintDefaults()
	//	return utils.IncorrectCommandLineParameters
	//}
	if err := f.amtOpStateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}
	return utils.Success
}
