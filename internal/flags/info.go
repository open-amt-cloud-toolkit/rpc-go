package flags

import (
	"flag"
	"rpc/pkg/utils"
)

type AmtInfoFlags struct {
	Ver      bool
	Bld      bool
	Sku      bool
	UUID     bool
	Mode     bool
	DNS      bool
	Cert     bool
	Ras      bool
	Lan      bool
	Hostname bool
}

// TODO: write unit tests
func (f *Flags) handleAMTInfo(amtInfoCommand *flag.FlagSet) utils.ReturnCode {
	amtInfoCommand.BoolVar(&f.AmtInfo.Ver, "ver", false, "BIOS Version")
	amtInfoCommand.BoolVar(&f.AmtInfo.Bld, "bld", false, "Build Number")
	amtInfoCommand.BoolVar(&f.AmtInfo.Sku, "sku", false, "Product SKU")
	amtInfoCommand.BoolVar(&f.AmtInfo.UUID, "uuid", false, "Unique Identifier")
	amtInfoCommand.BoolVar(&f.AmtInfo.Mode, "mode", false, "Current Control Mode")
	amtInfoCommand.BoolVar(&f.AmtInfo.DNS, "dns", false, "Domain Name Suffix")
	amtInfoCommand.BoolVar(&f.AmtInfo.Cert, "cert", false, "Certificate Hashes")
	amtInfoCommand.BoolVar(&f.AmtInfo.Ras, "ras", false, "Remote Access Status")
	amtInfoCommand.BoolVar(&f.AmtInfo.Lan, "lan", false, "LAN Settings")
	amtInfoCommand.BoolVar(&f.AmtInfo.Hostname, "hostname", false, "OS Hostname")

	if err := amtInfoCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}

	// runs locally
	f.Local = true

	defaultFlagCount := 2
	if f.JsonOutput {
		defaultFlagCount = defaultFlagCount + 1
	}
	if len(f.commandLineArgs) == defaultFlagCount {
		f.AmtInfo.Ver = true
		f.AmtInfo.Bld = true
		f.AmtInfo.Sku = true
		f.AmtInfo.UUID = true
		f.AmtInfo.Mode = true
		f.AmtInfo.DNS = true
		f.AmtInfo.Cert = false
		f.AmtInfo.Ras = true
		f.AmtInfo.Lan = true
		f.AmtInfo.Hostname = true
	}
	return utils.Success
}
