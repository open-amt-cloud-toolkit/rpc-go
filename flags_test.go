/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpc

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"rpc/pkg/pthi"
	"rpc/pkg/utils"
	"strings"
	"testing"

	"time"

	"github.com/stretchr/testify/assert"
)

const trickyPassword string = "!@#$%^&*(()-+="

type MockPTHICommands struct{}

func (c MockPTHICommands) Open(bool) error {
	return nil
}

func (c MockPTHICommands) Close() {}

func (c MockPTHICommands) Call([]byte, uint32) (result []byte, err error) {
	return []byte{}, nil
}

func (c MockPTHICommands) GetCodeVersions() (pthi.GetCodeVersionsResponse, error) {
	return pthi.GetCodeVersionsResponse{}, nil
}

func (c MockPTHICommands) GetUUID() (uuid string, err error) {
	return "", nil
}

func (c MockPTHICommands) GetControlMode() (state int, err error) {
	return 0, nil
}

func (c MockPTHICommands) GetDNSSuffix() (suffix string, err error) {
	return "", nil
}

func (c MockPTHICommands) GetCertificateHashes(pthi.AMTHashHandles) (hashEntryList []pthi.CertHashEntry, err error) {
	return []pthi.CertHashEntry{}, nil
}

func (c MockPTHICommands) GetRemoteAccessConnectionStatus() (RAStatus pthi.GetRemoteAccessConnectionStatusResponse, err error) {
	return pthi.GetRemoteAccessConnectionStatusResponse{}, nil
}

func (c MockPTHICommands) GetLocalSystemAccount() (localAccount pthi.GetLocalSystemAccountResponse, err error) {
	return pthi.GetLocalSystemAccountResponse{}, nil
}

func (c MockPTHICommands) GetLANInterfaceSettings(useWireless bool) (LANInterface pthi.GetLANInterfaceSettingsResponse, err error) {
	if useWireless {
		return pthi.GetLANInterfaceSettingsResponse{}, nil
	} else {
		return pthi.GetLANInterfaceSettingsResponse{
			Enabled:     1,
			Ipv4Address: 0,
			DhcpEnabled: 1,
			DhcpIpMode:  2,
			LinkStatus:  1,
			MacAddress:  [6]uint8{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		}, nil
	}
}

var testNetEnumerator = NetEnumerator{
	Interfaces: func() ([]net.Interface, error) {
		return []net.Interface{
			{
				Index: 0, MTU: 1200, Name: "wlanTest01",
				HardwareAddr: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				Flags:        0,
			},
			{
				Index: 0, MTU: 1200, Name: "errTest01",
				HardwareAddr: []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
				Flags:        0,
			},
			{
				Index: 0, MTU: 1200, Name: "ethTest01",
				HardwareAddr: []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
				Flags:        0,
			},
		}, nil
	},
	InterfaceAddrs: func(i *net.Interface) ([]net.Addr, error) {
		if i.Name == "errTest01" {
			return nil, errors.New("test message")
		} else {
			return []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.CIDRMask(8, 32),
				},
				&net.IPNet{
					IP:   net.ParseIP("::1234:5678"),
					Mask: net.CIDRMask(64, 128),
				},
				&net.IPNet{
					IP:   net.ParseIP("192.168.1.1"),
					Mask: net.CIDRMask(24, 32),
				},
			}, nil
		}
	},
}

func userInput(t *testing.T, input string) func() {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.Write([]byte(input))
	if err != nil {
		t.Error(err)
	}
	err = w.Close()
	if err != nil {
		t.Error(err)
	}
	stdin := os.Stdin
	os.Stdin = r
	return func() {
		os.Stdin = stdin
	}
}

func TestNewFlags(t *testing.T) {
	args := []string{"./rpc"}
	flags := NewFlags(args)
	assert.NotNil(t, flags)
}
func TestPrintUsage(t *testing.T) {
	executable := filepath.Base(os.Args[0])
	args := []string{executable}

	flags := NewFlags(args)
	output := flags.printUsage()
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"
	usage = usage + "Usage: " + executable + " COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Commands:\n"
	usage = usage + "  activate    Activate this device with a specified profile\n"
	usage = usage + "              Example: " + executable + " activate -u wss://server/activate --profile acmprofile\n"
	usage = usage + "  amtinfo     Displays information about AMT status and configuration\n"
	usage = usage + "              Example: " + executable + " amtinfo\n"
	usage = usage + "  deactivate  Deactivates this device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " deactivate -u wss://server/activate\n"
	usage = usage + "  maintenance Execute a maintenance task for the device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " maintenance syncclock -u wss://server/activate \n"
	usage = usage + "  version     Displays the current version of RPC and the RPC Protocol version\n"
	usage = usage + "              Example: " + executable + " version\n"
	usage = usage + "\nRun '" + executable + " COMMAND' for more information on a command.\n"
	assert.Equal(t, usage, output)
}

func TestPrintMaintenanceUsage(t *testing.T) {
	executable := filepath.Base(os.Args[0])
	args := []string{executable}
	flags := NewFlags(args)
	output := flags.printMaintenanceUsage()
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
	usage = usage + "\nRun '" + executable + " maintenance COMMAND -h' for more information on a command.\n"
	assert.Equal(t, usage, output)
}

func TestHandleActivateCommandNoFlags(t *testing.T) {
	args := []string{"./rpc", "activate"}
	flags := NewFlags(args)
	keepGoing, success := flags.handleActivateCommand()
	assert.EqualValues(t, keepGoing, false)
	assert.EqualValues(t, success, utils.IncorrectCommandLineParameters)
}
func TestHandleActivateCommand(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName", "-password", "Password"}
	flags := NewFlags(args)
	var AMTTimeoutDuration time.Duration = 120000000000
	expected := "activate --profile profileName"
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, true)
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, expected, flags.Command)
	assert.Equal(t, "Password", flags.Password)
	assert.Equal(t, "localhost", flags.LMSAddress)
	assert.Equal(t, "16992", flags.LMSPort)
	// 2m default
	assert.Equal(t, AMTTimeoutDuration, flags.AMTTimeoutDuration)
}

func TestHandleActivateCommandWithTimeOut(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName", "-password", "Password", "-t", "2s"}
	flags := NewFlags(args)
	var AMTTimeoutDuration time.Duration = 2000000000
	expected := "activate --profile profileName"
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, true)
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, expected, flags.Command)
	assert.Equal(t, "Password", flags.Password)
	assert.Equal(t, "localhost", flags.LMSAddress)
	assert.Equal(t, "16992", flags.LMSPort)
	assert.Equal(t, AMTTimeoutDuration, flags.AMTTimeoutDuration)
}
func TestHandleActivateCommandWithLMS(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName", "-lmsaddress", "1.1.1.1", "-lmsport", "99"}
	flags := NewFlags(args)
	expected := "activate --profile profileName"
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, true)
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, expected, flags.Command)
	assert.Equal(t, "1.1.1.1", flags.LMSAddress)
	assert.Equal(t, "99", flags.LMSPort)
}
func TestHandleActivateCommandWithENV(t *testing.T) {

	if err := os.Setenv("DNS_SUFFIX", "envdnssuffix.com"); err != nil {
		t.Error(err)
	}
	if err := os.Setenv("HOSTNAME", "envhostname"); err != nil {
		t.Error(err)
	}
	if err := os.Setenv("PROFILE", "envprofile"); err != nil {
		t.Error(err)
	}
	if err := os.Setenv("AMT_PASSWORD", "envpassword"); err != nil {
		t.Error(err)
	}

	args := []string{"./rpc", "activate", "-u", "wss://localhost"}
	flags := NewFlags(args)
	expected := "activate --profile envprofile"
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, true)
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "envprofile", flags.Profile)
	assert.Equal(t, expected, flags.Command)
	assert.Equal(t, "envpassword", flags.Password)
	os.Clearenv()
}

func TestHandleActivateCommandNoProfile(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost"}
	flags := NewFlags(args)
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.MissingOrIncorrectProfile)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandNoProxy(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-p"}
	flags := NewFlags(args)
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.MissingProxyAddressAndPort)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandNoHostname(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-h"}
	flags := NewFlags(args)
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.MissingHostname)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandNoDNSSuffix(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-d"}
	flags := NewFlags(args)
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.MissingDNSSuffix)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandMissingProfile(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile"}
	flags := NewFlags(args)
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.MissingOrIncorrectProfile)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandNoURL(t *testing.T) {
	args := []string{"./rpc", "activate", "-profile", "profileName"}

	flags := NewFlags(args)
	keepGoing, success := flags.handleActivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.MissingOrIncorrectURL)
	assert.Equal(t, "profileName", flags.Profile)
}

func TestHandleDeactivateCommandNoFlags(t *testing.T) {
	args := []string{"./rpc", "deactivate"}
	flags := NewFlags(args)
	keepGoing, success := flags.handleDeactivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.IncorrectCommandLineParameters)
}
func TestHandleDeactivateInvalidFlag(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-x"}

	flags := NewFlags(args)
	keepGoing, success := flags.handleDeactivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.IncorrectCommandLineParameters)
}

func TestHandleDeactivateCommandNoPasswordPrompt(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost"}
	expected := "deactivate --password password"
	defer userInput(t, "password")()
	flags := NewFlags(args)
	keepGoing, success := flags.handleDeactivateCommand()
	assert.Equal(t, keepGoing, true)
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, expected, flags.Command)
}
func TestHandleDeactivateCommandNoPasswordPromptEmpy(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost"}
	defer userInput(t, "")()
	flags := NewFlags(args)
	keepGoing, success := flags.handleDeactivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.MissingOrIncorrectPassword)
}
func TestHandleDeactivateCommandNoURL(t *testing.T) {
	args := []string{"./rpc", "deactivate", "--password", "password"}

	flags := NewFlags(args)
	keepGoing, success := flags.handleDeactivateCommand()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, success, utils.MissingOrIncorrectURL)
}
func TestHandleDeactivateCommand(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password"}
	expected := "deactivate --password password"
	flags := NewFlags(args)
	keepGoing, success := flags.handleDeactivateCommand()
	assert.Equal(t, keepGoing, true)
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, expected, flags.Command)
}
func TestHandleDeactivateCommandWithForce(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password", "-f"}
	expected := "deactivate --password password -f"
	flags := NewFlags(args)
	keepGoing, success := flags.handleDeactivateCommand()
	assert.Equal(t, keepGoing, true)
	assert.EqualValues(t, success, utils.Success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, expected, flags.Command)
}

func TestParseFlagsDeactivate(t *testing.T) {
	args := []string{"./rpc", "deactivate"}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, "deactivate", command)
}

func TestParseFlagsMaintenance(t *testing.T) {
	argUrl := "-u wss://localhost"
	argCurPw := "-password " + trickyPassword
	argSyncClock := "syncclock"
	argSyncHostname := "synchostname"
	argSyncIp := "syncip"
	argChangePw := "changepassword"
	newPassword := trickyPassword + "123"
	cmdBase := "./rpc maintenance"
	ipCfgNoParams := IPConfiguration{
		IpAddress: "192.168.1.1",
		Netmask:   "255.255.255.0",
	}
	ipCfgWithParams := IPConfiguration{
		IpAddress:    "10.20.30.40",
		Netmask:      "255.0.0.0",
		Gateway:      "10.0.0.0",
		PrimaryDns:   "8.8.8.8",
		SecondaryDns: "4.4.4.4",
	}
	ipCfgWithLookup := IPConfiguration{
		IpAddress:    ipCfgNoParams.IpAddress,
		Netmask:      ipCfgNoParams.Netmask,
		Gateway:      "10.0.0.0",
		PrimaryDns:   "1.2.3.4",
		SecondaryDns: "5.6.7.8",
	}
	tests := map[string]struct {
		cmdLine               string
		wantResult            int
		wantRpsCmd            string
		wantIPConfig          IPConfiguration
		wantNewStaticPassword string
		userInput             string
	}{
		// "should fail - required task": {
		// 	cmdLine:    cmdBase + " " + argUrl,
		// 	wantResult: utils.Success,
		// 	wantRpsCmd: "",
		// },
		"should fail with usage - no additional arguments": {
			cmdLine:    cmdBase,
			wantResult: utils.IncorrectCommandLineParameters,
			wantRpsCmd: "",
		},
		"should fail - required websocket URL": {
			cmdLine:    cmdBase + " " + argSyncClock,
			wantResult: utils.MissingOrIncorrectURL,
		},
		"should fail - required amt password": {
			cmdLine:    cmdBase + " " + argSyncClock + " " + argUrl,
			wantResult: utils.MissingOrIncorrectPassword,
			wantRpsCmd: "",
		},
		"should pass - syncclock": {
			cmdLine:    cmdBase + " " + argSyncClock + " " + argUrl + " " + argCurPw,
			wantResult: utils.Success,
			// translate arg from clock -> time
			wantRpsCmd: "maintenance -" + argCurPw + " --synctime",
		},
		"should pass - synchostname no params": {
			cmdLine:    cmdBase + " " + argSyncHostname + " " + argUrl + " " + argCurPw,
			wantResult: utils.Success,
			wantRpsCmd: "maintenance -" + argCurPw + " --" + argSyncHostname,
		},
		"should pass - syncip no params": {
			cmdLine:      cmdBase + " " + argSyncIp + " " + argUrl + " " + argCurPw,
			wantResult:   utils.Success,
			wantRpsCmd:   "maintenance -" + argCurPw + " --" + argSyncIp,
			wantIPConfig: ipCfgNoParams,
		},
		"should pass - syncip with params": {
			cmdLine: cmdBase + " " +
				argSyncIp +
				" -staticip " + ipCfgWithParams.IpAddress +
				" -netmask " + ipCfgWithParams.Netmask +
				" -gateway " + ipCfgWithParams.Gateway +
				" -primarydns " + ipCfgWithParams.PrimaryDns +
				" -secondarydns " + ipCfgWithParams.SecondaryDns +
				" " + argUrl + " " + argCurPw,
			wantResult:   utils.Success,
			wantRpsCmd:   "maintenance -" + argCurPw + " --" + argSyncIp,
			wantIPConfig: ipCfgWithParams,
		},
		"should pass - syncip with lookup": {
			cmdLine: cmdBase + " " +
				argSyncIp +
				" -gateway " + ipCfgWithLookup.Gateway +
				" -primarydns " + ipCfgWithLookup.PrimaryDns +
				" -secondarydns " + ipCfgWithLookup.SecondaryDns +
				" " + argUrl + " " + argCurPw,
			wantResult:   utils.Success,
			wantRpsCmd:   "maintenance -" + argCurPw + " --" + argSyncIp,
			wantIPConfig: ipCfgWithLookup,
		},
		"should fail - syncip bad ip address": {
			cmdLine:    cmdBase + " " + argSyncIp + " -staticip 322.299.0.0 " + argUrl + " " + argCurPw,
			wantResult: utils.MissingOrIncorrectStaticIP,
			wantRpsCmd: "",
		},
		"should pass - change password to random value": {
			cmdLine:    cmdBase + " " + argChangePw + " " + argUrl + " " + argCurPw,
			wantResult: utils.Success,
			wantRpsCmd: "maintenance -" + argCurPw + " --" + argChangePw,
		},
		"should pass - change password using static value": {
			cmdLine:               cmdBase + " " + argChangePw + " -static " + newPassword + " " + argUrl + " " + argCurPw,
			wantResult:            utils.Success,
			wantRpsCmd:            "maintenance -" + argCurPw + " --" + argChangePw,
			wantNewStaticPassword: newPassword,
		},
		"should pass - change password static value before other flags": {
			cmdLine:               cmdBase + " " + argChangePw + " -static " + newPassword + " " + argUrl + " " + argCurPw,
			wantResult:            utils.Success,
			wantRpsCmd:            "maintenance -" + argCurPw + " --" + argChangePw,
			wantNewStaticPassword: newPassword,
		},
		"should pass - change password static value after all flags": {
			cmdLine:               cmdBase + " " + argChangePw + " " + argUrl + " " + argCurPw + " -static " + newPassword,
			wantResult:            utils.Success,
			wantRpsCmd:            "maintenance -" + argCurPw + " --" + argChangePw,
			wantNewStaticPassword: newPassword,
		},
		"should pass - password user input": {
			cmdLine:    cmdBase + " " + argSyncClock + " " + argUrl,
			wantResult: utils.Success,
			wantRpsCmd: "maintenance -" + argCurPw + " --synctime",
			userInput:  trickyPassword,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			if tc.userInput != "" {
				defer userInput(t, tc.userInput)()
			}
			flags := NewFlags(args)
			flags.amtCommand.PTHI = MockPTHICommands{}
			flags.netEnumerator = testNetEnumerator
			gotCommand, keepGoing, gotResult := flags.ParseFlags()
			if gotResult == utils.Success {
				assert.Equal(t, keepGoing, true)
			} else {
				assert.Equal(t, keepGoing, false)
			}
			assert.Equal(t, tc.wantResult, gotResult)
			assert.Equal(t, "maintenance", gotCommand)
			assert.Equal(t, tc.wantRpsCmd, flags.Command)
			assert.Equal(t, tc.wantIPConfig, flags.IpConfiguration)
			assert.Equal(t, tc.wantNewStaticPassword, flags.NewStaticPassword)
		})
	}
}

func TestParseFlagsAMTInfo(t *testing.T) {
	args := []string{"./rpc", "amtinfo"}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.Success)
	assert.Equal(t, "amtinfo", command)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsAMTInfoJSON(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-json"}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.Success)
	assert.Equal(t, "amtinfo", command)
	assert.Equal(t, true, flags.JsonOutput)
}
func TestParseFlagsAMTInfoCert(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-cert"}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.Success)
	assert.Equal(t, "amtinfo", command)
	assert.Equal(t, false, flags.JsonOutput)
}
func TestParseFlagsAMTInfoOSDNSSuffix(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-dns"}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.Success)
	assert.Equal(t, "amtinfo", command)
	assert.Equal(t, false, flags.JsonOutput)
}
func TestParseFlagsActivate(t *testing.T) {
	args := []string{"./rpc", "activate"}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, "activate", command)
}
func TestParseFlagsVersion(t *testing.T) {
	args := []string{"./rpc", "version"}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.Success)
	assert.Equal(t, "version", command)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsVersionJSON(t *testing.T) {
	args := []string{"./rpc", "version", "-json"}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.Success)
	assert.Equal(t, "version", command)
	assert.Equal(t, true, flags.JsonOutput)
}

func TestParseFlagsNone(t *testing.T) {
	args := []string{"./rpc"}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, "", command)
}

func TestParseFlagsEmptyCommand(t *testing.T) {
	args := []string{"./rpc", ""}
	flags := NewFlags(args)
	command, keepGoing, result := flags.ParseFlags()
	assert.Equal(t, keepGoing, false)
	assert.EqualValues(t, result, utils.Success)
	assert.Equal(t, "", command)
}

func TestLookupEnvOrString_Default(t *testing.T) {
	args := []string{"./rpc", ""}
	flags := NewFlags(args)
	result := flags.lookupEnvOrString("URL", "")
	assert.Equal(t, "", result)
}
func TestLookupEnvOrString_Env(t *testing.T) {
	args := []string{"./rpc", ""}
	if err := os.Setenv("URL", "wss://localhost"); err != nil {
		t.Error(err)
	}
	flags := NewFlags(args)
	result := flags.lookupEnvOrString("URL", "")
	assert.Equal(t, "wss://localhost", result)
}

func TestLookupEnvOrBool_Default(t *testing.T) {
	args := []string{"./rpc", ""}
	flags := NewFlags(args)
	result := flags.lookupEnvOrBool("SKIP_CERT_CHECK", false)
	assert.Equal(t, false, result)
}
func TestLookupEnvOrBool_Env(t *testing.T) {
	args := []string{"./rpc", ""}

	if err := os.Setenv("SKIP_CERT_CHECK", "true"); err != nil {
		t.Error(err)
	}
	flags := NewFlags(args)
	result := flags.lookupEnvOrBool("SKIP_CERT_CHECK", false)
	assert.Equal(t, true, result)
}

func TestLookupEnvOrBool_EnvError(t *testing.T) {
	args := []string{"./rpc", ""}
	if err := os.Setenv("SKIP_CERT_CHECK", "notparsable"); err != nil {
		t.Error(err)
	}
	flags := NewFlags(args)
	result := flags.lookupEnvOrBool("SKIP_CERT_CHECK", false)
	assert.Equal(t, false, result)
}
