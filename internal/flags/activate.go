package flags

import (
	"fmt"
	"regexp"
	"rpc/pkg/utils"
)

func (f *Flags) handleActivateCommand() (bool, int) {
	f.amtActivateCommand.StringVar(&f.DNS, "d", f.lookupEnvOrString("DNS_SUFFIX", ""), "dns suffix override")
	f.amtActivateCommand.StringVar(&f.Hostname, "h", f.lookupEnvOrString("HOSTNAME", ""), "hostname override")
	f.amtActivateCommand.StringVar(&f.Profile, "profile", f.lookupEnvOrString("PROFILE", ""), "name of the profile to use")
	// use the Func call rather than StringVar to keep the default value out of the help/usage message
	f.amtActivateCommand.Func("name", "friendly name to associate with this device", func(flagValue string) error {
		f.FriendlyName = flagValue
		return nil
	})

	if len(f.commandLineArgs) == 2 {
		f.amtActivateCommand.PrintDefaults()
		return false, utils.IncorrectCommandLineParameters
	}
	if err := f.amtActivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		re := regexp.MustCompile(`: .*`)
		var errCode = utils.IncorrectCommandLineParameters
		switch re.FindString(err.Error()) {
		case ": -d":
			errCode = utils.MissingDNSSuffix
		case ": -p":
			errCode = utils.MissingProxyAddressAndPort
		case ": -h":
			errCode = utils.MissingHostname
		case ": -profile":
			errCode = utils.MissingOrIncorrectProfile
		default:
			errCode = utils.IncorrectCommandLineParameters
		}
		return false, errCode
	}

	if f.amtActivateCommand.Parsed() {
		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtActivateCommand.Usage()
			return false, utils.MissingOrIncorrectURL
		}
		if f.Profile == "" {
			fmt.Println("-profile flag is required and cannot be empty")
			f.amtActivateCommand.Usage()
			return false, utils.MissingOrIncorrectProfile
		}
	}
	f.Command = "activate --profile " + f.Profile
	return true, utils.Success
}
