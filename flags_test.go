/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpc

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFlags(t *testing.T) {
	args := []string{"./rpc"}
	flags := NewFlags(args)
	assert.NotNil(t, flags)
}
func TestPrintUsage(t *testing.T) {
	args := []string{"./rpc"}
	flags := NewFlags(args)
	output := flags.printUsage()
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, and status of AMT\n\n"
	usage = usage + "Usage: rpc COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Commands:\n"
	usage = usage + "  activate    Activate this device with a specified profile\n"
	usage = usage + "              Example: ./rpc activate -u wss://server/activate --profile acmprofile\n"
	usage = usage + "  deactivate  Deactivates this device. AMT password is required\n"
	usage = usage + "              Example: ./rpc deactivate -u wss://server/activate\n"
	usage = usage + "  maintenance Maintain this device.\n"
	usage = usage + "              Example: ./rpc maintenance -u wss://server/activate\n"
	usage = usage + "  amtinfo     Displays information about AMT status and configuration\n"
	usage = usage + "              Example: ./rpc amtinfo\n"
	usage = usage + "  version     Displays the current version of RPC and the RPC Protocol version\n"
	usage = usage + "              Example: ./rpc version\n"
	usage = usage + "\nRun 'rpc COMMAND' for more information on a command.\n"
	assert.Equal(t, usage, output)
}

func TestHandleActivateCommandNoFlags(t *testing.T) {
	args := []string{"./rpc", "activate"}
	flags := NewFlags(args)
	success := flags.handleActivateCommand()
	assert.False(t, success)
}
func TestHandleActivateCommand(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName", "-password", "Password"}
	flags := NewFlags(args)
	expected := "activate --profile profileName"
	success := flags.handleActivateCommand()
	assert.True(t, success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, expected, flags.Command)
	assert.Equal(t, "Password", flags.Password)
	assert.Equal(t, "localhost", flags.LMSAddress)
	assert.Equal(t, "16992", flags.LMSPort)
}
func TestHandleActivateCommandWithLMS(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName", "-lmsaddress", "1.1.1.1", "-lmsport", "99"}
	flags := NewFlags(args)
	expected := "activate --profile profileName"
	success := flags.handleActivateCommand()
	assert.True(t, success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, expected, flags.Command)
	assert.Equal(t, "1.1.1.1", flags.LMSAddress)
	assert.Equal(t, "99", flags.LMSPort)
}
func TestHandleActivateCommandWithENV(t *testing.T) {

	os.Setenv("DNS_SUFFIX", "envdnssuffix.com")
	os.Setenv("HOSTNAME", "envhostname")
	os.Setenv("PROFILE", "envprofile")
	os.Setenv("AMT_PASSWORD", "envpassword")

	args := []string{"./rpc", "activate", "-u", "wss://localhost"}
	flags := NewFlags(args)
	expected := "activate --profile envprofile"
	success := flags.handleActivateCommand()
	assert.True(t, success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "envprofile", flags.Profile)
	assert.Equal(t, expected, flags.Command)
	assert.Equal(t, "envpassword", flags.Password)
	os.Clearenv()
}

func TestHandleActivateCommandNoURL(t *testing.T) {
	args := []string{"./rpc", "activate", "-u", "wss://localhost"}
	flags := NewFlags(args)
	success := flags.handleActivateCommand()
	assert.False(t, success)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleActivateCommandNoProfile(t *testing.T) {
	args := []string{"./rpc", "activate", "-profile", "profileName"}

	flags := NewFlags(args)
	success := flags.handleActivateCommand()
	assert.False(t, success)
	assert.Equal(t, "profileName", flags.Profile)
}

func TestHandleDeactivateCommandNoFlags(t *testing.T) {
	args := []string{"./rpc", "deactivate"}

	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.False(t, success)
}
func TestHandleDeactivateCommandNoPasswordPrompt(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost"}
	expected := "deactivate --password password"
	input := []byte("password")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	_, err = w.Write(input)
	if err != nil {
		t.Error(err)
	}
	w.Close()

	stdin := os.Stdin
	// Restore stdin right after the test.
	defer func() { os.Stdin = stdin }()
	os.Stdin = r

	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.True(t, success)
	assert.Equal(t, expected, flags.Command)
}
func TestHandleDeactivateCommandNoPasswordPromptEmpy(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost"}
	input := []byte("")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	_, err = w.Write(input)
	if err != nil {
		t.Error(err)
	}
	w.Close()

	stdin := os.Stdin
	// Restore stdin right after the test.
	defer func() { os.Stdin = stdin }()
	os.Stdin = r

	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.False(t, success)
}
func TestHandleDeactivateCommandNoURL(t *testing.T) {
	args := []string{"./rpc", "deactivate", "--password", "password"}

	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.False(t, success)
}
func TestHandleDeactivateCommand(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password"}
	expected := "deactivate --password password"
	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.True(t, success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, expected, flags.Command)
}
func TestHandleDeactivateCommandWithForce(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password", "-f"}
	expected := "deactivate --password password -f"
	flags := NewFlags(args)
	success := flags.handleDeactivateCommand()
	assert.True(t, success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, expected, flags.Command)
}

func TestParseFlagsDeactivate(t *testing.T) {
	args := []string{"./rpc", "deactivate"}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
	assert.Equal(t, "deactivate", command)
}

func TestParseFlagsAMTInfo(t *testing.T) {
	args := []string{"./rpc", "amtinfo"}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
	assert.Equal(t, "amtinfo", command)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsAMTInfoJSON(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-json"}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
	assert.Equal(t, "amtinfo", command)
	assert.Equal(t, true, flags.JsonOutput)
}
func TestParseFlagsAMTInfoCert(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-cert"}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
	assert.Equal(t, "amtinfo", command)
	assert.Equal(t, false, flags.JsonOutput)
}
func TestParseFlagsAMTInfoOSDNSSuffix(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-dns"}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
	assert.Equal(t, "amtinfo", command)
	assert.Equal(t, false, flags.JsonOutput)
}
func TestParseFlagsActivate(t *testing.T) {
	args := []string{"./rpc", "activate"}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
	assert.Equal(t, "activate", command)
}
func TestParseFlagsVersion(t *testing.T) {
	args := []string{"./rpc", "version"}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
	assert.Equal(t, "version", command)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsVersionJSON(t *testing.T) {
	args := []string{"./rpc", "version", "-json"}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
	assert.Equal(t, "version", command)
	assert.Equal(t, true, flags.JsonOutput)
}

func TestParseFlagsNone(t *testing.T) {
	args := []string{"./rpc"}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
	assert.Equal(t, "", command)
}

func TestParseFlagsEmptyCommand(t *testing.T) {
	args := []string{"./rpc", ""}
	flags := NewFlags(args)
	command, result := flags.ParseFlags()
	assert.False(t, result)
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
	os.Setenv("URL", "wss://localhost")
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
	os.Setenv("SKIP_CERT_CHECK", "true")
	flags := NewFlags(args)
	result := flags.lookupEnvOrBool("SKIP_CERT_CHECK", false)
	assert.Equal(t, true, result)
}

func TestLookupEnvOrBool_EnvError(t *testing.T) {
	args := []string{"./rpc", ""}
	os.Setenv("SKIP_CERT_CHECK", "notparsable")
	flags := NewFlags(args)
	result := flags.lookupEnvOrBool("SKIP_CERT_CHECK", false)
	assert.Equal(t, false, result)
}
