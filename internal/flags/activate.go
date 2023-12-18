package flags

import (
	"fmt"
	"reflect"
	"regexp"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

func (f *Flags) handleActivateCommand() utils.ReturnCode {
	f.amtActivateCommand.StringVar(&f.DNS, "d", f.lookupEnvOrString("DNS_SUFFIX", ""), "dns suffix override")
	f.amtActivateCommand.StringVar(&f.Hostname, "h", f.lookupEnvOrString("HOSTNAME", ""), "hostname override")
	f.amtActivateCommand.StringVar(&f.Profile, "profile", f.lookupEnvOrString("PROFILE", ""), "name of the profile to use")
	f.amtActivateCommand.BoolVar(&f.Local, "local", false, "activate amt locally")
	f.amtActivateCommand.BoolVar(&f.UseCCM, "ccm", false, "activate in client control mode (CCM)")
	f.amtActivateCommand.BoolVar(&f.UseACM, "acm", false, "activate in admin control mode (ACM)")
	// use the Func call rather than StringVar to keep the default value out of the help/usage message
	f.amtActivateCommand.Func("name", "friendly name to associate with this device", func(flagValue string) error {
		f.FriendlyName = flagValue
		return nil
	})
	f.amtActivateCommand.BoolVar(&f.SkipIPRenew, "skipIPRenew", false, "skip DHCP renewal of the IP address if AMT becomes enabled")
	// for local activation in ACM mode need a few more items
	f.amtActivateCommand.StringVar(&f.configContent, "config", "", "specify a config file or smb: file share URL")
	f.amtActivateCommand.StringVar(&f.LocalConfig.ACMSettings.AMTPassword, "amtPassword", f.lookupEnvOrString("AMT_PASSWORD", ""), "amt password")
	f.amtActivateCommand.StringVar(&f.LocalConfig.ACMSettings.ProvisioningCert, "provisioningCert", f.lookupEnvOrString("PROVISIONING_CERT", ""), "provisioning certificate")
	f.amtActivateCommand.StringVar(&f.LocalConfig.ACMSettings.ProvisioningCertPwd, "provisioningCertPwd", f.lookupEnvOrString("PROVISIONING_CERT_PASSWORD", ""), "provisioning certificate password")

	if len(f.commandLineArgs) == 2 {
		f.amtActivateCommand.PrintDefaults()
		return utils.IncorrectCommandLineParameters
	}
	if err := f.amtActivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		re := regexp.MustCompile(`: .*`)
		var rc = utils.IncorrectCommandLineParameters
		switch re.FindString(err.Error()) {
		case ": -d":
			rc = utils.MissingDNSSuffix
		case ": -p":
			rc = utils.MissingProxyAddressAndPort
		case ": -h":
			rc = utils.MissingHostname
		case ": -profile":
			rc = utils.MissingOrIncorrectProfile
		default:
			rc = utils.IncorrectCommandLineParameters
		}
		return rc
	}
	if f.Local && f.URL != "" {
		fmt.Println("provide either a 'url' or a 'local', but not both")
		return utils.InvalidParameterCombination
	}

	if !f.Local {
		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtActivateCommand.Usage()
			return utils.MissingOrIncorrectURL
		}
		if f.Profile == "" {
			fmt.Println("-profile flag is required and cannot be empty")
			f.amtActivateCommand.Usage()
			return utils.MissingOrIncorrectProfile
		}
		if f.UUID != "" {
			rc := f.validateUUIDOverride()
			if rc != utils.Success {
				f.amtActivateCommand.Usage()
				return rc
			}
			fmt.Println("Warning: Overriding UUID prevents device from connecting to MPS")
		}
	} else {
		if !f.UseCCM && !f.UseACM || f.UseCCM && f.UseACM {
			fmt.Println("must specify -ccm or -acm, but not both")
			return utils.InvalidParameterCombination
		}

		if f.UseACM {
			rc := f.handleLocalConfig()
			if rc != utils.Success {
				return rc
			}
			// Check if all fields are filled
			v := reflect.ValueOf(f.LocalConfig.ACMSettings)
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).Interface() == "" { // not checking 0 since authenticantProtocol can and needs to be 0 for EAP-TLS
					log.Error("Missing value for field: ", v.Type().Field(i).Name)
					return utils.IncorrectCommandLineParameters
				}
			}

		}

		// Only for CCM it asks for password.
		if !f.UseACM && f.Password == "" {
			if _, rc := f.ReadPasswordFromUser(); rc != utils.Success {
				return utils.MissingOrIncorrectPassword
			}
		}
		f.LocalConfig.Password = f.Password

		if f.UUID != "" {
			fmt.Println("-uuid cannot be use in local activation")
			f.amtActivateCommand.Usage()
			return utils.InvalidParameterCombination
		}
	}
	return utils.Success
}
