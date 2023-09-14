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
	UserCert bool
	Ras      bool
	Lan      bool
	Hostname bool
}

func (f *Flags) handleAMTInfo(amtInfoCommand *flag.FlagSet) utils.ReturnCode {
	// runs locally
	f.Local = true

	amtInfoCommand.BoolVar(&f.AmtInfo.Ver, "ver", false, "BIOS Version")
	amtInfoCommand.BoolVar(&f.AmtInfo.Bld, "bld", false, "Build Number")
	amtInfoCommand.BoolVar(&f.AmtInfo.Sku, "sku", false, "Product SKU")
	amtInfoCommand.BoolVar(&f.AmtInfo.UUID, "uuid", false, "Unique Identifier")
	amtInfoCommand.BoolVar(&f.AmtInfo.Mode, "mode", false, "Current Control Mode")
	amtInfoCommand.BoolVar(&f.AmtInfo.DNS, "dns", false, "Domain Name Suffix")
	amtInfoCommand.BoolVar(&f.AmtInfo.Cert, "cert", false, "System Certificate Hashes (and User Certificates if AMT password is provided)")
	amtInfoCommand.BoolVar(&f.AmtInfo.UserCert, "userCert", false, "User Certificates only. AMT password is required")
	amtInfoCommand.BoolVar(&f.AmtInfo.Ras, "ras", false, "Remote Access Status")
	amtInfoCommand.BoolVar(&f.AmtInfo.Lan, "lan", false, "LAN Settings")
	amtInfoCommand.BoolVar(&f.AmtInfo.Hostname, "hostname", false, "OS Hostname")
	amtInfoCommand.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT Password")

	if err := amtInfoCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}

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
		f.AmtInfo.Ras = true
		f.AmtInfo.Lan = true
		f.AmtInfo.Hostname = true
	}

	// no password - same behavior only cert hashes
	// with password - shows user certs too
	if f.AmtInfo.Cert && f.Password != "" {
		f.AmtInfo.UserCert = true
	}

	// user certs need the amt password for the local wsman connection
	if f.AmtInfo.UserCert && f.Password == "" {
		if _, errCode := f.ReadPasswordFromUser(); errCode != 0 {
			return utils.MissingOrIncorrectPassword
		}
	}

	return utils.Success
}
