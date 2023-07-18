/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"os"
	"rpc/internal/amt"
	"rpc/internal/flags"
	"rpc/internal/local"
	"rpc/internal/rps"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

const AccessErrMsg = "Failed to execute due to access issues. " +
	"Please ensure that Intel ME is present, " +
	"the MEI driver is installed, " +
	"and the runtime has administrator or root privileges."

func checkAccess() (int, error) {
	amtCommand := amt.NewAMTCommand()
	result, err := amtCommand.Initialize()
	if result != utils.Success || err != nil {
		return utils.AmtNotDetected, err
	}
	return utils.Success, nil
}

func runRPC(args []string) int {
	flags, resultCode := parseCommandLine(args)
	if resultCode != utils.Success {
		return resultCode
	}
	if flags.Local {
		resultCode = local.ExecuteCommand(flags)
	} else {
		resultCode = rps.ExecuteCommand(flags)
	}
	return resultCode
}

func parseCommandLine(args []string) (*flags.Flags, int) {
	//process flags
	flags := flags.NewFlags(args)
	resultCode := flags.ParseFlags()

	if flags.Verbose {
		log.SetLevel(log.TraceLevel)
	} else {
		lvl, err := log.ParseLevel(flags.LogLevel)
		if err != nil {
			log.Warn(err)
			log.SetLevel(log.InfoLevel)
		} else {
			log.SetLevel(lvl)
		}
	}

	if flags.JsonOutput {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
	}
	return flags, resultCode
}

func main() {
	status, err := checkAccess()
	if status != utils.Success {
		if err != nil {
			log.Error(err.Error())
		}
		log.Error(AccessErrMsg)
		os.Exit(status)
	}
	status = runRPC(os.Args)
	if err != nil {
		log.Error(err.Error())
	}
	os.Exit(status)
}
