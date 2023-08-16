package flags

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"rpc/internal/amt"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

func (f *Flags) printMaintenanceUsage() string {
	executable := filepath.Base(os.Args[0])
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"
	usage = usage + "Usage: " + executable + " maintenance COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Maintenance Commands:\n"
	usage = usage + "  changepassword Change the AMT password. A random password is generated by default. Specify -static to set manually. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance changepassword -u wss://server/activate\n"
	usage = usage + "  syncclock      Sync the host OS clock to AMT. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance syncclock -u wss://server/activate\n"
	usage = usage + "  synchostname   Sync the hostname of the client to AMT. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance synchostname -u wss://server/activate\n"
	usage = usage + "  syncip         Sync the IP configuration of the host OS to AMT Network Settings. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance syncip -staticip 192.168.1.7 -netmask 255.255.255.0 -gateway 192.168.1.1 -primarydns 8.8.8.8 -secondarydns 4.4.4.4 -u wss://server/activate\n"
	usage = usage + "                 If a static ip is not specified, the ip address and netmask of the host OS is used\n"
	usage = usage + "  addwifisettings Add or modify WiFi settings in AMT. AMT password is required. A config.yml or command line flags must be provided for all settings. This command runs without cloud interaction.\n"
	usage = usage + "                 Example: " + executable + " maintenance addwifisettings -password YourAMTPassword -config wificonfig.yaml\n"
	usage = usage + "\nRun '" + executable + " maintenance COMMAND -h' for more information on a command.\n"
	fmt.Println(usage)
	return usage
}

func (f *Flags) handleMaintenanceCommand() int {
	//validation section
	if len(f.commandLineArgs) == 2 {
		f.printMaintenanceUsage()
		return utils.IncorrectCommandLineParameters
	}

	var errCode = utils.Success

	f.SubCommand = f.commandLineArgs[2]
	switch f.SubCommand {
	case "addwifisettings":
		errCode = f.handleMaintenanceAddWifiSettings()
		break
	case "syncclock":
		errCode = f.handleMaintenanceSyncClock()
		break
	case "synchostname":
		errCode = f.handleMaintenanceSyncHostname()
		break
	case "syncip":
		errCode = f.handleMaintenanceSyncIP()
		break
	case "changepassword":
		errCode = f.handleMaintenanceSyncChangePassword()
		break
	default:
		f.printMaintenanceUsage()
		errCode = utils.IncorrectCommandLineParameters
		break
	}
	if errCode != utils.Success {
		return errCode
	}

	if f.Password == "" {
		if _, errCode := f.ReadPasswordFromUser(); errCode != 0 {
			return utils.MissingOrIncorrectPassword
		}
	}
	f.LocalConfig.Password = f.Password

	// if this is a local command, then we dont care about -u or what task/command since its not going to the cloud
	if !f.Local {
		if f.URL == "" {
			fmt.Print("\n-u flag is required and cannot be empty\n\n")
			f.printMaintenanceUsage()
			return utils.MissingOrIncorrectURL
		}
	}

	return utils.Success
}

func (f *Flags) handleMaintenanceAddWifiSettings() int {
	// this is an implied local command
	f.Local = true

	f.amtMaintenanceAddWiFiSettingsCommand.StringVar(&f.configContent, "config", "", "specify a config file ")

	f.amtMaintenanceAddWiFiSettingsCommand.StringVar(&f.LocalConfig.IEEE8021XSettings.Name, "name", "", "specify name")
	f.amtMaintenanceAddWiFiSettingsCommand.IntVar(&f.LocalConfig.IEEE8021XSettings.AuthenticationMethod, "authenticationMethod", 0, "specify authentication method")
	f.amtMaintenanceAddWiFiSettingsCommand.IntVar(&f.LocalConfig.IEEE8021XSettings.EncryptionMethod, "encryptionMethod", 0, "specify encryption method")
	f.amtMaintenanceAddWiFiSettingsCommand.StringVar(&f.LocalConfig.IEEE8021XSettings.SSID, "ssid", "", "specify ssid")
	f.amtMaintenanceAddWiFiSettingsCommand.StringVar(&f.LocalConfig.IEEE8021XSettings.Username, "username", "", "specify username")
	f.amtMaintenanceAddWiFiSettingsCommand.IntVar(&f.LocalConfig.IEEE8021XSettings.AuthenticationProtocol, "authenticationProtocol", 0, "specify authentication protocol")
	f.amtMaintenanceAddWiFiSettingsCommand.IntVar(&f.LocalConfig.IEEE8021XSettings.Priority, "priority", 0, "specify priority")
	f.amtMaintenanceAddWiFiSettingsCommand.StringVar(&f.LocalConfig.IEEE8021XSettings.ClientCert, "clientCert", "", "specify client certificate")
	f.amtMaintenanceAddWiFiSettingsCommand.StringVar(&f.LocalConfig.IEEE8021XSettings.CACert, "caCert", "", "specify CA certificate")
	f.amtMaintenanceAddWiFiSettingsCommand.StringVar(&f.LocalConfig.IEEE8021XSettings.PrivateKey, "privateKey", "", "specify private key")

	if err := f.amtMaintenanceAddWiFiSettingsCommand.Parse(f.commandLineArgs[3:]); err != nil {
		f.amtMaintenanceAddWiFiSettingsCommand.Usage()
		return utils.IncorrectCommandLineParameters
	}

	if f.JsonOutput {
		log.SetFormatter(&log.JSONFormatter{})
	}
	resultCode := f.handleLocalConfig()
	if resultCode != utils.Success {
		return resultCode
	}
	// Check if all fields are filled
	v := reflect.ValueOf(f.LocalConfig.IEEE8021XSettings)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Interface() == "" { // not checking 0 since authenticantProtocol can and needs to be 0 for EAP-TLS
			log.Error("Missing value for field: ", v.Type().Field(i).Name)
			return utils.IncorrectCommandLineParameters
		}
	}

	return utils.Success
}
func (f *Flags) handleMaintenanceSyncClock() int {
	if err := f.amtMaintenanceSyncClockCommand.Parse(f.commandLineArgs[3:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}
	return utils.Success
}

func (f *Flags) handleMaintenanceSyncHostname() int {
	var err error
	if err = f.amtMaintenanceSyncHostnameCommand.Parse(f.commandLineArgs[3:]); err != nil {
		f.amtMaintenanceSyncHostnameCommand.Usage()
		return utils.IncorrectCommandLineParameters
	}
	amtCommand := amt.NewAMTCommand()
	if f.HostnameInfo.DnsSuffixOS, err = amtCommand.GetOSDNSSuffix(); err != nil {
		log.Error(err)
	}
	f.HostnameInfo.Hostname, err = os.Hostname()
	if err != nil {
		log.Error(err)
		return utils.OSNetworkInterfacesLookupFailed
	} else if f.HostnameInfo.Hostname == "" {
		log.Error("OS hostname is not available")
		return utils.OSNetworkInterfacesLookupFailed
	}
	return utils.Success
}

// wrap the flag.Func method signature with the assignment value
func validateIP(assignee *string) func(string) error {
	return func(val string) error {
		if net.ParseIP(val) == nil {
			return errors.New("not a valid ip address")
		}
		*assignee = val
		return nil
	}
}

func (f *Flags) handleMaintenanceSyncIP() int {
	f.amtMaintenanceSyncIPCommand.Func(
		"staticip",
		"IP address to be assigned to AMT - if not specified, the IP Address of the active OS newtork interface is used",
		validateIP(&f.IpConfiguration.IpAddress))
	f.amtMaintenanceSyncIPCommand.Func(
		"netmask",
		"Network mask to be assigned to AMT - if not specified, the Network mask of the active OS newtork interface is used",
		validateIP(&f.IpConfiguration.Netmask))
	f.amtMaintenanceSyncIPCommand.Func("gateway", "Gateway address to be assigned to AMT", validateIP(&f.IpConfiguration.Gateway))
	f.amtMaintenanceSyncIPCommand.Func("primarydns", "Primary DNS to be assigned to AMT", validateIP(&f.IpConfiguration.PrimaryDns))
	f.amtMaintenanceSyncIPCommand.Func("secondarydns", "Secondary DNS to be assigned to AMT", validateIP(&f.IpConfiguration.SecondaryDns))

	if err := f.amtMaintenanceSyncIPCommand.Parse(f.commandLineArgs[3:]); err != nil {
		f.amtMaintenanceSyncIPCommand.Usage()
		// Parse the error message to find the problematic flag.
		// The problematic flag is of the following format '-' followed by flag name and then a ':'
		var errCode int
		re := regexp.MustCompile(`-.*:`)
		switch re.FindString(err.Error()) {
		case "-netmask:":
			errCode = utils.MissingOrIncorrectNetworkMask
		case "-staticip:":
			errCode = utils.MissingOrIncorrectStaticIP
		case "-gateway:":
			errCode = utils.MissingOrIncorrectGateway
		case "-primarydns:":
			errCode = utils.MissingOrIncorrectPrimaryDNS
		case "-secondarydns:":
			errCode = utils.MissingOrIncorrectSecondaryDNS
		default:
			errCode = utils.IncorrectCommandLineParameters
		}
		return errCode
	} else if len(f.IpConfiguration.IpAddress) != 0 {
		return utils.Success
	}

	amtLanIfc, err := f.amtCommand.GetLANInterfaceSettings(false)
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}

	ifaces, err := f.netEnumerator.Interfaces()
	if err != nil {
		log.Error(err)
		return utils.OSNetworkInterfacesLookupFailed
	}

	for _, i := range ifaces {
		if len(f.IpConfiguration.IpAddress) != 0 {
			break
		}
		if i.HardwareAddr.String() != amtLanIfc.MACAddress {
			continue
		}
		addrs, _ := f.netEnumerator.InterfaceAddrs(&i)
		if err != nil {
			continue
		}
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok &&
				ipnet.IP.To4() != nil &&
				!ipnet.IP.IsLoopback() {
				f.IpConfiguration.IpAddress = ipnet.IP.String()
				f.IpConfiguration.Netmask = net.IP(ipnet.Mask).String()
			}
		}
	}

	if len(f.IpConfiguration.IpAddress) == 0 {
		log.Errorf("static ip address not found")
		return utils.OSNetworkInterfacesLookupFailed
	}
	return utils.Success
}

func (f *Flags) handleMaintenanceSyncChangePassword() int {
	f.amtMaintenanceChangePasswordCommand.StringVar(&f.StaticPassword, "static", "", "specify a new password for AMT")
	if err := f.amtMaintenanceChangePasswordCommand.Parse(f.commandLineArgs[3:]); err != nil {
		f.amtMaintenanceChangePasswordCommand.Usage()
		return utils.IncorrectCommandLineParameters
	}
	return utils.Success
}
