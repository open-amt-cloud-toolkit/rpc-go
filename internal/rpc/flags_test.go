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
	usage = usage + "  activate   Activate this device with a specified profile\n"
	usage = usage + "             Example: ./rpc activate -u wss://server/activate --profile acmprofile\n"
	usage = usage + "  deactivate Deactivates this device. AMT password is required\n"
	usage = usage + "             Example: ./rpc deactivate -u wss://server/activate\n"
	usage = usage + "  amtinfo    Displays information about AMT status and configuration\n"
	usage = usage + "             Example: ./rpc amtinfo\n"
	usage = usage + "  version    Displays the current version of RPC and the RPC Protocol version\n"
	usage = usage + "             Example: ./rpc version\n"
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
	args := []string{"./rpc", "activate", "-u", "wss://localhost", "-profile", "profileName"}
	flags := NewFlags(args)
	expected := "activate --profile profileName"
	success := flags.handleActivateCommand()
	assert.True(t, success)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, "profileName", flags.Profile)
	assert.Equal(t, expected, flags.Command)
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
