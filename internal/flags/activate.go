package flags

import (
	"fmt"
	"regexp"
	"rpc/internal/config"
	"rpc/pkg/utils"
)

func (f *Flags) handleActivateCommand() (bool, int) {
	f.amtActivateCommand.StringVar(&f.DNS, "d", f.lookupEnvOrString("DNS_SUFFIX", ""), "dns suffix override")
	f.amtActivateCommand.StringVar(&f.Hostname, "h", f.lookupEnvOrString("HOSTNAME", ""), "hostname override")
	f.amtActivateCommand.StringVar(&f.Profile, "profile", f.lookupEnvOrString("PROFILE", ""), "name of the profile to use")
	f.amtActivateCommand.BoolVar(&f.Local, "local", false, "activate amt locally")
	f.amtActivateCommand.BoolVar(&f.UseCCM, "ccm", false, "activate in client control mode (CCM)")
	// f.amtActivateCommand.BoolVar(&f.UseACM, "acm", false, "activate in admin control model (ACM)")
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
	if f.Local && f.URL != "" {
		fmt.Println("provide either a 'url' or a 'local', but not both")
		return false, utils.InvalidParameters
	}
	//if f.Local {
	// if !f.UseCCM && !f.UseACM || f.UseCCM && f.UseACM {
	// 	fmt.Println("must specify -ccm or -acm, but not both")
	// 	return false, utils.InvalidParameters
	// }
	//}

	if !f.Local {
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
	} else {
		if errCode := f.checkCurrentMode(); errCode != 0 {
			return false, errCode
		}
		if f.Password == "" {
			if _, errCode := f.readPasswordFromUser(); errCode != 0 {
				return false, utils.MissingOrIncorrectPassword
			}
		}
		f.UseCCM = true
		f.LocalConfig = &config.Config{}
		f.LocalConfig.Password = f.Password

		return true, utils.Success
	}

	f.Command = "activate --profile " + f.Profile
	return true, utils.Success
}

func (f *Flags) checkCurrentMode() int {
	controlMode, err := f.amtCommand.GetControlMode()
	if err != nil {
		fmt.Println("Unable to determine current control mode.")
		return utils.ActivationFailed
	}
	if controlMode != 0 {
		fmt.Println("Device is already activated")
		return utils.UnableToActivate
	}
	return utils.Success
}
