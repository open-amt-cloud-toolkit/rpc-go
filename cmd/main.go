/**********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"os"
	"rpc/config"
	"rpc/internal/amt"
	"rpc/internal/command"
	"rpc/internal/flags"
	"rpc/internal/local"
	// "rpc/internal/rps"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

const AccessErrMsg = "Failed to execute due to access issues. " +
	"Please ensure that Intel ME is present, " +
	"the MEI driver is installed, " +
	"and the runtime has administrator or root privileges."

func checkAccess() error {
	amtCommand := amt.NewAMTCommand()
	err := amtCommand.Initialize()
	if err != nil {
		return err
	}
	return nil
}

func runRPC(args []string) error {
	cfg := &config.Config{}
	result := command.Execute(args, cfg)
	if result != 0 {
		return utils.IncorrectCommandLineParameters
	}

	if cfg.IsLocal {
	    err := local.ExecuteCommand(cfg)
		if err != nil {
			return err
		}
	}
	// flags, err := parseCommandLine(args)
	// if err != nil {
	// 	return err
	// }
	// if flags.Local {
	// 	err = local.ExecuteCommand(flags)
	// } else {
	// 	err = rps.ExecuteCommand(flags)
	// }
	return nil
}

func parseCommandLine(args []string) (*flags.Flags, error) {
	//process flags
	flags := flags.NewFlags(args, utils.PR)
	error := flags.ParseFlags()

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
		log.SetFormatter(&log.JSONFormatter{
			DisableHTMLEscape: true,
		})
	} else {
		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
	}
	return flags, error
}

func main() {
	// err := checkAccess()
	// if err != nil {
	// 	log.Error(AccessErrMsg)
	// 	handleErrorAndExit(err)
	// }

	err := runRPC(os.Args)
	if err != nil {
		handleErrorAndExit(err)
	}
}

func handleErrorAndExit(err error) {
	if customErr, ok := err.(utils.CustomError); ok {
		if err != utils.HelpRequested {
			log.Error(customErr.Error())
		}
		os.Exit(customErr.Code)
	} else {
		log.Error(err.Error())
		os.Exit(utils.GenericFailure.Code)
	}
}
